#!/usr/bin/env python3
"""Compare OxyJWT with common Python JWT libraries.

The script intentionally keeps the benchmark simple and transparent. It signs
and verifies the same payload repeatedly across HMAC, RSA, RSA-PSS, ECDSA, and
EdDSA algorithms, then prints operations per second. Optional libraries and
unsupported algorithm/library combinations are reported as zero throughput.
"""

from __future__ import annotations

import argparse
import gc
import json
import statistics
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable


Payload = dict[str, object]
Key = str | bytes | object


@dataclass(frozen=True)
class AlgorithmCase:
    name: str
    family: str
    signing_key: Key
    verification_key: Key


@dataclass(frozen=True)
class LibraryAdapter:
    name: str
    encode: Callable[[Payload, str, Key], str]
    decode: Callable[[str, str, Key], Payload]
    prepare_signing_key: Callable[[str, Key, str], Key]
    prepare_verification_key: Callable[[str, Key, str], Key]


@dataclass(frozen=True)
class PreparedCase:
    library: str
    algorithm: str
    encode: Callable[[], str]
    decode: Callable[[], Payload]


@dataclass(frozen=True)
class SkippedCase:
    library: str
    algorithm: str
    reason: str


@dataclass(frozen=True)
class BenchmarkResult:
    algorithm: str
    library: str
    operation: str
    iterations: int
    rounds: int
    mean_seconds: float
    median_seconds: float
    ops_per_second: float


def private_pem(key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def public_pem(key: Any) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def build_algorithm_cases(selected_algorithms: set[str] | None = None) -> list[AlgorithmCase]:
    from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa

    secret = "benchmark-secret-with-at-least-64-bytes-for-hs512-comparison-padding"
    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ec256_key = ec.generate_private_key(ec.SECP256R1())
    ec384_key = ec.generate_private_key(ec.SECP384R1())
    ed_key = ed25519.Ed25519PrivateKey.generate()

    rsa_private = private_pem(rsa_key)
    rsa_public = public_pem(rsa_key)
    ec256_private = private_pem(ec256_key)
    ec256_public = public_pem(ec256_key)
    ec384_private = private_pem(ec384_key)
    ec384_public = public_pem(ec384_key)
    ed_private = private_pem(ed_key)
    ed_public = public_pem(ed_key)

    cases = [
        AlgorithmCase(name="HS256", family="HMAC", signing_key=secret, verification_key=secret),
        AlgorithmCase(name="HS384", family="HMAC", signing_key=secret, verification_key=secret),
        AlgorithmCase(name="HS512", family="HMAC", signing_key=secret, verification_key=secret),
        AlgorithmCase(name="RS256", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="RS384", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="RS512", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="PS256", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="PS384", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="PS512", family="RSA", signing_key=rsa_private, verification_key=rsa_public),
        AlgorithmCase(name="ES256", family="ECDSA", signing_key=ec256_private, verification_key=ec256_public),
        AlgorithmCase(name="ES384", family="ECDSA", signing_key=ec384_private, verification_key=ec384_public),
        AlgorithmCase(name="EdDSA", family="EdDSA", signing_key=ed_private, verification_key=ed_public),
    ]
    if selected_algorithms is None:
        return cases
    return [case for case in cases if case.name in selected_algorithms]


def load_adapters() -> list[LibraryAdapter]:
    adapters: list[LibraryAdapter] = []

    try:
        import oxyjwt

        def oxy_encode(payload: Payload, algorithm: str, key: Key) -> str:
            signing_key = oxy_key(oxyjwt.EncodingKey, algorithm, key)
            return oxyjwt.encode(payload, signing_key, algorithm=algorithm)

        def oxy_decode(token: str, algorithm: str, key: Key) -> Payload:
            verification_key = oxy_key(oxyjwt.DecodingKey, algorithm, key)
            return oxyjwt.decode(token, verification_key, algorithms=[algorithm])

        adapters.append(
            LibraryAdapter(
                name="OxyJWT",
                encode=oxy_encode,
                decode=oxy_decode,
                prepare_signing_key=lambda algorithm, key, key_mode: oxy_key(
                    oxyjwt.EncodingKey,
                    algorithm,
                    key,
                ),
                prepare_verification_key=lambda algorithm, key, key_mode: oxy_key(
                    oxyjwt.DecodingKey,
                    algorithm,
                    key,
                ),
            )
        )
    except ImportError:
        pass

    try:
        import jwt

        adapters.append(
            LibraryAdapter(
                name="PyJWT",
                encode=lambda payload, algorithm, key: jwt.encode(payload, key, algorithm=algorithm),
                decode=lambda token, algorithm, key: jwt.decode(token, key, algorithms=[algorithm]),
                prepare_signing_key=prepare_python_signing_key,
                prepare_verification_key=prepare_python_verification_key,
            )
        )
    except ImportError:
        pass

    try:
        import jose.jwt

        adapters.append(
            LibraryAdapter(
                name="python-jose",
                encode=lambda payload, algorithm, key: jose.jwt.encode(
                    payload,
                    key_text(key),
                    algorithm=algorithm,
                ),
                decode=lambda token, algorithm, key: jose.jwt.decode(
                    token,
                    key_text(key),
                    algorithms=[algorithm],
                ),
                prepare_signing_key=lambda algorithm, key, key_mode: key,
                prepare_verification_key=lambda algorithm, key, key_mode: key,
            )
        )
    except ImportError:
        pass

    try:
        import authlib.jose

        def authlib_encode(payload: Payload, algorithm: str, key: Key) -> str:
            header = {"alg": algorithm}
            token = authlib.jose.jwt.encode(header, payload, key)
            return token.decode("utf-8") if isinstance(token, bytes) else token

        def authlib_decode(token: str, algorithm: str, key: Key) -> Payload:
            claims = authlib.jose.jwt.decode(token, key)
            return dict(claims)

        adapters.append(
            LibraryAdapter(
                name="Authlib",
                encode=authlib_encode,
                decode=authlib_decode,
                prepare_signing_key=prepare_python_signing_key,
                prepare_verification_key=prepare_python_verification_key,
            )
        )
    except ImportError:
        pass

    return adapters


def oxy_key(key_class: type, algorithm: str, key: Key) -> Key:
    if not isinstance(key, (str, bytes)):
        return key
    if algorithm.startswith("HS"):
        return key
    if algorithm.startswith(("RS", "PS")):
        return key_class.from_rsa_pem(key)
    if algorithm.startswith("ES"):
        return key_class.from_ec_pem(key)
    if algorithm == "EdDSA":
        return key_class.from_ed_pem(key)
    raise ValueError(f"unsupported algorithm: {algorithm}")


def key_text(key: Key) -> Key:
    return key.decode("utf-8") if isinstance(key, bytes) else key


def prepare_python_signing_key(algorithm: str, key: Key, key_mode: str) -> Key:
    if key_mode != "cached" or algorithm.startswith("HS"):
        return key

    from cryptography.hazmat.primitives.serialization import load_pem_private_key

    return load_pem_private_key(as_bytes(key), password=None)


def prepare_python_verification_key(algorithm: str, key: Key, key_mode: str) -> Key:
    if key_mode != "cached" or algorithm.startswith("HS"):
        return key

    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    return load_pem_public_key(as_bytes(key))


def as_bytes(key: Key) -> bytes:
    if isinstance(key, bytes):
        return key
    if isinstance(key, str):
        return key.encode("utf-8")
    raise TypeError(f"expected str or bytes key, got {type(key).__name__}")


def bench_operation(
    func: Callable[[], object],
    *,
    iterations: int,
    rounds: int,
    warmup: int,
) -> tuple[float, float, float]:
    timings: list[float] = []

    gc.collect()
    was_enabled = gc.isenabled()
    gc.disable()
    try:
        for _ in range(warmup):
            func()
        for _ in range(rounds):
            started = time.perf_counter()
            for _ in range(iterations):
                func()
            timings.append(time.perf_counter() - started)
    finally:
        if was_enabled:
            gc.enable()

    mean_seconds = statistics.mean(timings)
    median_seconds = statistics.median(timings)
    ops_per_second = iterations / mean_seconds if mean_seconds else float("inf")
    return mean_seconds, median_seconds, ops_per_second


def prepare_cases(
    selected_algorithms: set[str] | None = None,
    competitor_key_mode: str = "pem",
) -> tuple[list[PreparedCase], list[SkippedCase]]:
    payload: Payload = {
        "sub": "user-123",
        "role": "admin",
        "exp": 4_102_444_800,
    }
    prepared: list[PreparedCase] = []
    skipped: list[SkippedCase] = []

    for algorithm_case in build_algorithm_cases(selected_algorithms):
        for adapter in load_adapters():
            try:
                signing_key = adapter.prepare_signing_key(
                    algorithm_case.name,
                    algorithm_case.signing_key,
                    competitor_key_mode,
                )
                verification_key = adapter.prepare_verification_key(
                    algorithm_case.name,
                    algorithm_case.verification_key,
                    competitor_key_mode,
                )
                token = adapter.encode(
                    payload,
                    algorithm_case.name,
                    signing_key,
                )
                decoded = adapter.decode(
                    token,
                    algorithm_case.name,
                    verification_key,
                )
                if decoded["sub"] != payload["sub"]:
                    raise RuntimeError("decoded an unexpected payload")
            except Exception as exc:
                skipped.append(
                    SkippedCase(
                        library=adapter.name,
                        algorithm=algorithm_case.name,
                        reason=f"{type(exc).__name__}: {exc}",
                    )
                )
                continue

            encode_key = signing_key
            decode_key = verification_key
            prepared.append(
                PreparedCase(
                    library=adapter.name,
                    algorithm=algorithm_case.name,
                    encode=lambda adapter=adapter, algorithm_case=algorithm_case, encode_key=encode_key: adapter.encode(
                        payload,
                        algorithm_case.name,
                        encode_key,
                    ),
                    decode=lambda adapter=adapter, algorithm_case=algorithm_case, token=token, decode_key=decode_key: adapter.decode(
                        token,
                        algorithm_case.name,
                        decode_key,
                    ),
                )
            )

    return prepared, skipped


def run_benchmark(
    iterations: int,
    rounds: int,
    warmup: int,
    selected_algorithms: set[str] | None = None,
    competitor_key_mode: str = "pem",
) -> tuple[list[BenchmarkResult], list[SkippedCase]]:
    results: list[BenchmarkResult] = []
    prepared, skipped = prepare_cases(selected_algorithms, competitor_key_mode)
    for case in prepared:
        for operation, func in (
            ("encode", case.encode),
            ("decode", case.decode),
        ):
            mean_seconds, median_seconds, ops_per_second = bench_operation(
                func,
                iterations=iterations,
                rounds=rounds,
                warmup=warmup,
            )
            results.append(
                BenchmarkResult(
                    algorithm=case.algorithm,
                    library=case.library,
                    operation=operation,
                    iterations=iterations,
                    rounds=rounds,
                    mean_seconds=mean_seconds,
                    median_seconds=median_seconds,
                    ops_per_second=ops_per_second,
                )
            )

    for item in skipped:
        for operation in ("encode", "decode"):
            results.append(
                BenchmarkResult(
                    algorithm=item.algorithm,
                    library=item.library,
                    operation=operation,
                    iterations=iterations,
                    rounds=rounds,
                    mean_seconds=0.0,
                    median_seconds=0.0,
                    ops_per_second=0.0,
                )
            )

    return sorted(
        results,
        key=lambda result: (result.algorithm, result.operation, result.library),
    ), skipped


def print_table(results: list[BenchmarkResult], skipped: list[SkippedCase]) -> None:
    if not results:
        print("No supported JWT libraries are installed.")
        return

    headers = ("Algorithm", "Library", "Operation", "Mean ms", "Median ms", "Ops/sec")
    rows = [
        (
            result.algorithm,
            result.library,
            result.operation,
            f"{result.mean_seconds * 1000:.3f}",
            f"{result.median_seconds * 1000:.3f}",
            f"{result.ops_per_second:,.0f}",
        )
        for result in results
    ]
    widths = [
        max(len(str(row[index])) for row in (headers, *rows))
        for index in range(len(headers))
    ]

    print(" | ".join(value.ljust(widths[index]) for index, value in enumerate(headers)))
    print("-+-".join("-" * width for width in widths))
    for row in rows:
        print(" | ".join(value.ljust(widths[index]) for index, value in enumerate(row)))

    print_summary(results)


def print_summary(results: list[BenchmarkResult]) -> None:
    print("\nWinners:")
    for (algorithm, operation), result in benchmark_winners(results):
        print(f"- {algorithm} {operation}: {result.library} ({result.ops_per_second:,.0f} ops/sec)")


def write_json(results: list[BenchmarkResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps([result.__dict__ for result in results], indent=2) + "\n",
        encoding="utf-8",
    )


def write_markdown(results: list[BenchmarkResult], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        "# JWT Library Benchmark Results",
        "",
        "| Algorithm | Library | Operation | Mean ms | Median ms | Ops/sec |",
        "| --- | --- | --- | ---: | ---: | ---: |",
    ]
    for result in results:
        lines.append(
            "| "
            f"{result.algorithm} | "
            f"{result.library} | "
            f"{result.operation} | "
            f"{result.mean_seconds * 1000:.3f} | "
            f"{result.median_seconds * 1000:.3f} | "
            f"{result.ops_per_second:,.0f} |"
        )
    lines.extend(["", "## Winners", ""])
    for (algorithm, operation), result in benchmark_winners(results):
        lines.append(f"- `{algorithm}` `{operation}`: **{result.library}** ({result.ops_per_second:,.0f} ops/sec)")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def benchmark_winners(results: list[BenchmarkResult]) -> list[tuple[tuple[str, str], BenchmarkResult]]:
    winners: dict[tuple[str, str], BenchmarkResult] = {}
    for result in results:
        key = (result.algorithm, result.operation)
        current = winners.get(key)
        if current is None or result.ops_per_second > current.ops_per_second:
            winners[key] = result
    return sorted(winners.items())


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--iterations", type=int, default=1_000)
    parser.add_argument("--rounds", type=int, default=3)
    parser.add_argument("--warmup", type=int, default=100)
    parser.add_argument(
        "--competitor-key-mode",
        choices=("pem", "cached"),
        default="pem",
        help="Use PEM bytes for competitors or preloaded cryptography key objects where supported.",
    )
    parser.add_argument(
        "--algorithms",
        default="all",
        help="Comma-separated algorithms to benchmark, or 'all'.",
    )
    parser.add_argument("--json", type=Path, help="Write raw results to a JSON file.")
    parser.add_argument("--markdown", type=Path, help="Write results to a Markdown table.")
    return parser.parse_args()


def parse_algorithms(value: str) -> set[str] | None:
    if value.strip().lower() == "all":
        return None

    known = {case.name for case in build_algorithm_cases()}
    selected = {item.strip() for item in value.split(",") if item.strip()}
    unknown = selected - known
    if unknown:
        raise SystemExit(f"Unknown algorithms: {', '.join(sorted(unknown))}")
    return selected


def main() -> None:
    args = parse_args()
    results, skipped = run_benchmark(
        iterations=args.iterations,
        rounds=args.rounds,
        warmup=args.warmup,
        selected_algorithms=parse_algorithms(args.algorithms),
        competitor_key_mode=args.competitor_key_mode,
    )
    print_table(results, skipped)

    if args.json:
        write_json(results, args.json)
    if args.markdown:
        write_markdown(results, args.markdown)


if __name__ == "__main__":
    main()

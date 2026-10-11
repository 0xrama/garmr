"""Public artifact contracts, using the checked-in stock and reference images."""
import contextlib
import importlib
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "poc"))
import mtk_cert as cert
import build_native_20_5_12 as native12
import build_native_20_5_14 as native14


def quiet(function, *args, **kwargs):
    with contextlib.redirect_stdout(io.StringIO()):
        return function(*args, **kwargs)


def flipped(data, offset):
    out = bytearray(data)
    out[offset] ^= 1
    return bytes(out)


class ArtifactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = {}
        for build, module, artifact in (
            ("20-5-12", native12, "cancunf-fenrir-full-20-5-12.img"),
            ("20-5-14", native14, "cancunf-native-full-20-5-14.img"),
        ):
            directory = ROOT / "firmware" / ("V1TDS35H.83-" + build)
            cls.fixtures[build] = (
                module, (directory / "lk.img").read_bytes(),
                (ROOT / "poc" / artifact).read_bytes(),
                (directory / "tee.img").read_bytes(),
            )

    def test_reference_artifacts_and_stock_certificates(self):
        for build, (module, stock, artifact, tee) in self.fixtures.items():
            with self.subTest(build=build):
                patched = quiet(module.apply_patches, stock)
                self.assertEqual(cert.apply_cert_bypass(patched, module.CERT_TARGETS), artifact)
                self.assertTrue(quiet(module.verify_patches, stock, artifact))
                for image in (stock, artifact, tee):
                    self.assertTrue(quiet(cert.verify, image))
                payload = cert.parse_parts(artifact)[0].data_off
                self.assertFalse(quiet(cert.verify, flipped(artifact, payload)))

    def test_container_boundaries_and_complete_signed_inventory(self):
        for build, (_, stock, _, tee) in self.fixtures.items():
            for kind, image in (("lk", stock), ("tee", tee)):
                parts = cert.parse_parts(image)
                first_triple = image[:parts[2].end]
                missing_end = bytearray(image)
                struct.pack_into("<I", missing_end, parts[-1].off + 64, 0)
                for label, broken in (
                    ("first triple", first_triple), ("truncated payload", image[:-1]),
                    ("missing end", bytes(missing_end)), ("junk", image + b"junk"),
                    ("zero tail", image + b"\0"),
                ):
                    with self.subTest(build=build, kind=kind, case=label):
                        with self.assertRaises(ValueError):
                            cert.parse_parts(broken)
                        with self.assertRaises(ValueError):
                            quiet(cert.verify, broken)
                forged = bytearray(first_triple)
                struct.pack_into("<I", forged, parts[2].off + 64, 1)
                renamed = bytearray(image)
                renamed[parts[3].off + 8:parts[3].off + 40] = b"unexpected".ljust(32, b"\0")
                reordered = image[parts[3].off:parts[5].end] + image[:parts[3].off] + image[parts[5].end:]
                for label, broken in (("partial", bytes(forged)), ("name", bytes(renamed)),
                                      ("order", reordered)):
                    with self.subTest(build=build, kind=kind, case=label):
                        with self.assertRaises(ValueError):
                            quiet(cert.verify, broken)

    def test_required_patch_partitions_and_exact_stock_sites(self):
        for build, (module, stock, artifact, _) in self.fixtures.items():
            with self.subTest(build=build):
                parts = cert.parse_parts(stock)
                partial = bytearray(stock[:parts[2].end])
                struct.pack_into("<I", partial, parts[2].off + 64, 1)
                with self.assertRaises(ValueError):
                    quiet(module.apply_patches, bytes(partial))
                # Derive a changed site from reference payloads, not PATCHES.
                old = stock[parts[0].data_off:parts[0].data_off + parts[0].dsize]
                target = cert.parse_parts(artifact)[0]
                new = artifact[target.data_off:target.data_off + target.dsize]
                site = next(i for i, (a, b) in enumerate(zip(old, new)) if a != b)
                broken = bytearray(artifact)
                broken[target.data_off + site] = old[site]
                self.assertFalse(quiet(module.verify_patches, stock, bytes(broken)))
                # Cert overrides make the corruption cryptographically valid;
                # the patch verifier must still reject the wrong stock site.
                resigned = cert.apply_cert_bypass(bytes(broken), module.CERT_TARGETS)
                self.assertTrue(quiet(cert.verify, resigned))
                self.assertFalse(quiet(module.verify_patches, stock, resigned))

    def test_canonical_verifier(self):
        verifier = importlib.import_module("verify_poc")
        for build, (module, stock, artifact, _) in self.fixtures.items():
            with self.subTest(build=build):
                self.assertTrue(quiet(verifier.verify, stock, artifact, build=build))
                other = "20-5-14" if build == "20-5-12" else "20-5-12"
                self.assertFalse(quiet(verifier.verify, stock, artifact, build=other))
                part = cert.parse_parts(artifact)[0]
                corrupted = flipped(artifact, part.data_off)
                self.assertFalse(quiet(verifier.verify, stock, corrupted, build=build))
                unexpected = cert.apply_cert_bypass(corrupted, module.CERT_TARGETS)
                self.assertTrue(quiet(cert.verify, unexpected))
                self.assertFalse(quiet(verifier.verify, stock, unexpected, build=build))
                self.assertFalse(quiet(verifier.verify, stock, artifact + b"junk", build=build))
        _, stock, artifact, _ = self.fixtures["20-5-12"]
        self.assertTrue(quiet(verifier.verify, stock, artifact))

    def test_sign_rejects_unknown_targets_and_invalid_certificates_without_output(self):
        _, stock, _, _ = self.fixtures["20-5-12"]
        with self.assertRaises(ValueError):
            cert.apply_cert_bypass(stock, {"lk", "nonexistent"})
        # Last CERT1 byte is signature data: corrupt crypto, not DER structure.
        c1 = cert.parse_parts(stock)[1]
        invalid = flipped(stock, c1.data_off + c1.dsize - 1)
        self.assertFalse(quiet(cert.verify, invalid))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "input.img"
            output = Path(directory) / "output.img"
            for label, data, targets in (("bad signature", invalid, "lk,bl2_ext,aee"),
                                         ("unknown target", stock, "nonexistent")):
                with self.subTest(case=label):
                    source.write_bytes(data)
                    result = subprocess.run(
                        [sys.executable, str(ROOT / "poc" / "mtk_cert.py"), "sign",
                         str(source), "-o", str(output), "--partitions", targets],
                        capture_output=True, text=True, check=False,
                    )
                    self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertFalse(output.exists(), "failed signing wrote an artifact")


    def test_packaged_module_matches_sources_and_refuses_other_firmware(self):
        with zipfile.ZipFile(ROOT / "poc" / "cancunf-km-trustlet-patch-v2.zip") as archive:
            for name in ("common.sh", "post-fs-data.sh", "service.sh", "module.prop",
                         "0706000000000000000000000000004d.tlbin"):
                self.assertEqual(archive.read(name), (ROOT / "poc" / "trustlet_patch" / name).read_bytes())
            with tempfile.TemporaryDirectory() as directory:
                module = Path(directory)
                archive.extractall(module)
                tools = module / "bin"
                tools.mkdir()
                getprop = tools / "getprop"
                getprop.write_text("#!/bin/sh\nprintf '%s\\n' 'motorola/cancunf:15/V1TDS35H.83-20-5-14/test:user/release-keys'\n")
                getprop.chmod(0o755)
                # Never let a regression invoke real host mount/service tools.
                for name in ("mount", "setprop", "stop", "start"):
                    tool = tools / name
                    tool.write_text("#!/bin/sh\necho 'UNEXPECTED ACTION' >&2\nexit 1\n")
                    tool.chmod(0o755)
                env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"]}
                for name in ("post-fs-data.sh", "service.sh"):
                    result = subprocess.run(["/bin/sh", str(module / name)], env=env,
                                            capture_output=True, text=True, check=False, timeout=5)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertNotIn("UNEXPECTED ACTION", result.stderr)
                self.assertIn("REFUSED: vendor firmware", (module / "module.log").read_text())


if __name__ == "__main__":
    unittest.main()

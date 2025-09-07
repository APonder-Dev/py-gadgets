from pathlib import Path
import tempfile
import os
from py_gadgets.tools.bigfiles import main


def test_bigfiles_runs(tmp_path: Path, capsys):
    # Create files: 1MB, 10MB, 0.5MB
    sizes = [1_048_576, 10_485_760, 524_288]
    for i, sz in enumerate(sizes):
        p = tmp_path / f"file{i}.bin"
        with open(p, "wb") as f:
            f.write(b"\0" * sz)

    # show top 2 >=1MB
    rc = main(["-p", str(tmp_path), "-n", "2", "-m", "1"])
    captured = capsys.readouterr().out
    assert rc == 0
    assert "10.0 MB" in captured
    assert "1.0 MB" in captured
    assert "0.5 MB" not in captured

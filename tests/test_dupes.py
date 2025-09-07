from pathlib import Path
from py_gadgets.tools.dupes import main


def test_dupes_finds_duplicates(tmp_path: Path, capsys):
    a = tmp_path / "a.txt"
    b = tmp_path / "sub" / "b.txt"
    b.parent.mkdir(parents=True, exist_ok=True)
    content = b"same-content"
    a.write_bytes(content)
    b.write_bytes(content)

    rc = main(["-p", str(tmp_path)])
    out = capsys.readouterr().out
    assert rc == 0
    assert "hash=" in out
    assert "a.txt" in out and "b.txt" in out

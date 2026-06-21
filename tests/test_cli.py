"""Tests for the fullauth command-line utilities (secret, check)."""

import pytest

from fastapi_fullauth.cli import main


def test_secret_prints_key(capsys):
    rc = main(["secret"])
    out = capsys.readouterr().out.strip()
    assert rc == 0
    assert len(out) >= 32


def test_no_command_errors():
    # argparse exits with code 2 when the required subcommand is missing.
    with pytest.raises(SystemExit) as exc:
        main([])
    assert exc.value.code == 2


def test_check_reports_effective_config(capsys, monkeypatch, tmp_path):
    monkeypatch.setenv("FULLAUTH_SECRET_KEY", "x" * 40)
    monkeypatch.chdir(tmp_path)  # avoid picking up a project .env during the test run
    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "Effective configuration:" in out
    assert "backend (default)" in out
    assert "secret key" in out


def test_check_warns_on_generated_secret(capsys, monkeypatch, tmp_path):
    monkeypatch.delenv("FULLAUTH_SECRET_KEY", raising=False)
    monkeypatch.chdir(tmp_path)  # no .env here, so the key is generated
    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 0
    assert "generated" in out
    assert "FULLAUTH_SECRET_KEY is not set" in out


def test_check_reports_config_error(capsys, monkeypatch, tmp_path):
    # PASSKEY_ENABLED without PASSKEY_RP_ID fails config validation.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("FULLAUTH_SECRET_KEY", "x" * 40)
    monkeypatch.setenv("FULLAUTH_PASSKEY_ENABLED", "true")
    rc = main(["check"])
    out = capsys.readouterr().out
    assert rc == 1
    assert "Config error" in out
    assert "PASSKEY_RP_ID" in out

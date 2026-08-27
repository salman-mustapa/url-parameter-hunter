import pytest
from app.artifacts.hash_cracker import HashIntelligenceEngine
from app.artifacts.sql_parser import SqlDumpParser

def test_hash_intelligence_engine_md5_cracking():
    # Admin MD5
    is_cracked, plaintext, algo = HashIntelligenceEngine.attempt_crack("21232f297a57a5a743894a0e4a801fc3")
    assert is_cracked is True
    assert plaintext == "admin"
    assert algo == "md5"

    # User MD5
    is_cracked, plaintext, algo = HashIntelligenceEngine.attempt_crack("ee11cbb19052e40b07aac0ca060c23ee")
    assert is_cracked is True
    assert plaintext == "user"
    assert algo == "md5"

def test_hash_intelligence_engine_target_mutation():
    # User specific password e.g. faperta -> faperta
    is_cracked, plaintext, algo = HashIntelligenceEngine.attempt_crack(
        "c5b772dc7711df6f3b1da4e81e09c578",
        associated_username="faperta"
    )
    assert is_cracked is True
    assert plaintext == "faperta"

def test_sql_dump_parser_with_hash_enrichment():
    sample_sql = """
    -- MySQL Dump Test
    CREATE TABLE `t_users` (
      `id` int(11) NOT NULL,
      `username` varchar(50) NOT NULL,
      `password` varchar(32) NOT NULL,
      `email` varchar(100) NOT NULL
    );

    INSERT INTO `t_users` (`id`, `username`, `password`, `email`) VALUES
    (1, 'admin', '21232f297a57a5a743894a0e4a801fc3', 'admin@example.com'),
    (2, 'user', 'ee11cbb19052e40b07aac0ca060c23ee', 'user@example.com');
    """
    res = SqlDumpParser.parse(sample_sql)
    assert res["vendor"] == "MySQL / MariaDB"
    assert len(res["tables"]) == 1
    t0 = res["tables"][0]
    assert t0["name"] == "t_users"
    assert len(t0["columns"]) == 4
    assert len(t0["sample_rows"]) == 2

    # Check hashes and plaintext
    hashes = res["extracted_hashes"]
    assert len(hashes) == 2
    admin_h = next(h for h in hashes if h.get("associated_user") == "admin")
    assert admin_h["is_cracked"] is True
    assert admin_h["plaintext"] == "admin"

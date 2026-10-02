import asyncio
from backend.adaptive.tier3_slm_rag import Tier3Adaptive
from backend.adaptive.rag_index import ParserRAG

async def test_tier3():
    rag = ParserRAG()
    tier3 = Tier3Adaptive(rag)
    hints = {
        "candidate_mappings": [
            {"source_field": "var_5", "candidate_target": "destination.port", "evidence_type": "UNRESOLVED", "value_type": "PORT", "value_sample": "5678"},
            {"source_field": "message", "candidate_target": "message", "evidence_type": "UNRESOLVED", "value_type": "STRING", "value_sample": "john tuesday logins from 5678"}
        ],
        "unresolved_fields": ["message"],
        "regex_pattern": ""
    }
    
    spec, conf, detail = await tier3.adapt("john tuesday logins from 5678", hints)
    print("SPEC:", spec)
    print("DETAIL:", detail)

if __name__ == "__main__":
    asyncio.run(test_tier3())

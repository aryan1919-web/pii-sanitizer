# Free Hosting Plan for PII Sanitizer

## Project Summary

Your PII Sanitizer is a **FastAPI Python backend** with:
- **ML models**: DeBERTa-v3 NER, spaCy, Presidio
- **OCR**: PaddleOCR (PaddlePaddle)
- **Database**: SQLite
- **Frontend**: Static HTML/CSS/JS served by FastAPI
- **Heavy deps**: `torch`, `transformers`, `paddlepaddle`, `paddleocr`, `spacy` (~2GB+ total)

---

## Free Hosting Options Comparison

| Platform | Free RAM | Disk | Works? |
|----------|----------|------|--------|
| Render | 512MB | 512MB | ❌ Not enough RAM |
| Railway | 512MB | 1GB | ❌ Same issue |
| Fly.io | 256MB | 1GB | ❌ Way too small |
| **Hugging Face Spaces** | **16GB** | **50GB** | **✅ Perfect** |
| Vercel/Netlify | 1GB/10s | N/A | ❌ Serverless, timeouts |
| PythonAnywhere | 512MB | 512MB | ❌ Too small |

## ✅ Recommendation: Hugging Face Spaces (Docker SDK)

**Why?** It's the only free platform with enough resources (16GB RAM, 50GB disk) to run PyTorch + DeBERTa + PaddleOCR.

- Free forever, no credit card
- URL: `https://YOUR_USERNAME-pii-sanitizer.hf.space`
- Docker support = runs your FastAPI app as-is
- Sleeps after 48h inactivity (wakes on request, ~30-60s cold start)

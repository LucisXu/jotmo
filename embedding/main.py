#!/usr/bin/env python3
"""
Jotmo Embedding Service
使用 Qwen3-Embedding-0.6B 生成文本嵌入向量
"""

import os
from typing import List, Union
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import torch
from transformers import AutoTokenizer, AutoModel

app = FastAPI(title="Jotmo Embedding Service")

# 模型配置
MODEL_NAME = "Qwen/Qwen3-Embedding-0.6B"
DEVICE = "cuda" if torch.cuda.is_available() else "cpu"

# 全局变量
tokenizer = None
model = None


class EmbedRequest(BaseModel):
    texts: Union[str, List[str]]


class EmbedResponse(BaseModel):
    embeddings: List[List[float]]
    dimension: int


def mean_pooling(model_output, attention_mask):
    """对 token embeddings 进行平均池化"""
    token_embeddings = model_output[0]
    input_mask_expanded = attention_mask.unsqueeze(-1).expand(token_embeddings.size()).float()
    return torch.sum(token_embeddings * input_mask_expanded, 1) / torch.clamp(input_mask_expanded.sum(1), min=1e-9)


@app.on_event("startup")
async def load_model():
    """启动时加载模型"""
    global tokenizer, model
    print(f"Loading model {MODEL_NAME} on {DEVICE}...")

    tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME, trust_remote_code=True)
    model = AutoModel.from_pretrained(MODEL_NAME, trust_remote_code=True)
    model.to(DEVICE)
    model.eval()

    print(f"Model loaded successfully on {DEVICE}")


@app.get("/health")
async def health():
    """健康检查"""
    return {"status": "ok", "device": DEVICE, "model": MODEL_NAME}


@app.post("/embed", response_model=EmbedResponse)
async def embed(request: EmbedRequest):
    """生成文本嵌入向量"""
    if model is None or tokenizer is None:
        raise HTTPException(status_code=503, detail="Model not loaded")

    # 统一为列表格式
    texts = request.texts if isinstance(request.texts, list) else [request.texts]

    if not texts:
        raise HTTPException(status_code=400, detail="No texts provided")

    try:
        # 对于 Qwen3-Embedding，需要添加指令前缀
        # 对于检索任务，文档不需要指令，查询需要指令
        # 这里我们对所有文本统一处理（作为文档存储）

        # Tokenize
        encoded = tokenizer(
            texts,
            padding=True,
            truncation=True,
            max_length=512,
            return_tensors="pt"
        )
        encoded = {k: v.to(DEVICE) for k, v in encoded.items()}

        # 生成嵌入
        with torch.no_grad():
            outputs = model(**encoded)
            embeddings = mean_pooling(outputs, encoded["attention_mask"])
            # L2 归一化
            embeddings = torch.nn.functional.normalize(embeddings, p=2, dim=1)

        # 转换为 Python 列表
        embeddings_list = embeddings.cpu().numpy().tolist()
        dimension = len(embeddings_list[0]) if embeddings_list else 0

        return EmbedResponse(embeddings=embeddings_list, dimension=dimension)

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/embed/batch")
async def embed_batch(request: EmbedRequest):
    """批量生成嵌入（同 /embed，为兼容性保留）"""
    return await embed(request)


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("EMBEDDING_PORT", "8089"))
    uvicorn.run(app, host="0.0.0.0", port=port)

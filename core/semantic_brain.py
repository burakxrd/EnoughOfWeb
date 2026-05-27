"""
EnoughOfWeb — Native Semantic Brain
Offline LLM Question-Answering using HuggingFace Transformers.
Strictly requires GPU (CUDA) for execution.
"""

import torch
from transformers import AutoTokenizer, AutoModelForQuestionAnswering


class SemanticBrain:
    """
    Local Natural Language Processor using a QA model.
    Forces execution on GPU device 0.
    """

    def __init__(self, model_name="savasy/bert-base-turkish-squad"):
        """
        Initialize the offline NLP pipeline.
        Raises an exception if CUDA is not available.
        """
        if not torch.cuda.is_available():
            raise RuntimeError(
                "CRITICAL ERROR: CUDA is not available. "
                "Semantic Brain requires a dedicated GPU (RTX 5060) and cannot fallback to CPU."
            )

        print(f"[*] Initializing Semantic Brain on GPU (CUDA)...")
        print(f"[*] Model: {model_name}")
        
        self.device = torch.device("cuda:0")
        self.tokenizer = AutoTokenizer.from_pretrained(model_name)
        self.model = AutoModelForQuestionAnswering.from_pretrained(model_name).to(self.device)
        self.model.eval()
        
        print("[+] Semantic Brain initialized successfully.")

    def ask(self, context: str, question: str) -> dict:
        """
        Ask a question based on the provided context (e.g. DOM text).
        
        Args:
            context: The text to search within.
            question: The natural language question.
            
        Returns:
            dict containing:
                - 'answer': The extracted answer string.
                - 'score': Confidence score (0.0 to 1.0).
        """
        if not context or not context.strip():
            return {"answer": "", "score": 0.0}
        if not question or not question.strip():
            return {"answer": "", "score": 0.0}

        try:
            inputs = self.tokenizer(question, context, return_tensors="pt", truncation=True, max_length=512).to(self.device)
            with torch.no_grad():
                outputs = self.model(**inputs)
            
            answer_start_scores = outputs.start_logits
            answer_end_scores = outputs.end_logits
            
            # Get the most likely beginning of answer with the argmax of the score
            answer_start = torch.argmax(answer_start_scores)
            # Get the most likely end of answer with the argmax of the score
            answer_end = torch.argmax(answer_end_scores) + 1
            
            answer = self.tokenizer.convert_tokens_to_string(self.tokenizer.convert_ids_to_tokens(inputs["input_ids"][0][answer_start:answer_end]))
            
            # Simple pseudo-probability for confidence (softmax of the selected start/end logits)
            start_probs = torch.nn.functional.softmax(answer_start_scores, dim=1)
            end_probs = torch.nn.functional.softmax(answer_end_scores, dim=1)
            score = (start_probs[0][answer_start] * end_probs[0][answer_end - 1]).item()
            
            # Clean up the output
            answer = answer.strip()
            if answer.startswith("<s>"): answer = answer[3:].strip()
            if answer.endswith("</s>"): answer = answer[:-4].strip()
            
            return {"answer": answer, "score": score}
        except Exception as e:
            print(f"[!] SemanticBrain error: {e}")
            return {"answer": "", "score": 0.0}

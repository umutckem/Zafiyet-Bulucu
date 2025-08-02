from groq import Groq
import os
from dotenv import load_dotenv

load_dotenv()
api_key = os.getenv("GROQ_API_KEY")
client = Groq(api_key=api_key)

def suggest_mitigation(cve_description):
    messages = [
        {"role": "system", "content": "Sen siber güvenlik uzmanı gibi davranan yardımsever bir asistansın."},
        {"role": "user", "content": f"Bu güvenlik açığına karşı nasıl önlem alınabilir?\n\n{cve_description}"}
    ]

    completion = client.chat.completions.create(
        model="meta-llama/llama-4-scout-17b-16e-instruct",
        messages=messages,
        temperature=0.7,
        max_completion_tokens=1024,
        top_p=1,
        stream=False,
    )

    return completion.choices[0].message.content

import google.generativeai as genai

genai.configure(api_key="YOUR_API_KEY")

models = genai.list_models()

for m in models:
    print(m.name, m.supported_generation_methods)

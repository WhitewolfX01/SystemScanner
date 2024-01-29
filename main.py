import requests
import json
from langchain_community.llms import HuggingFaceHub
from langchain.chains import LLMChain
from langchain.prompts import PromptTemplate 

def savejson(header):
    with open('response.json', 'w') as file:
        json.dump(
            header,
            file,
            sort_keys=True,
            indent=4,
            separators=(',', ': ')
        )

def chatbot_api(description):
    repo_id = "tiiuae/falcon-7b-instruct"
    huggingfacehub_api_token = "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"
    llm = HuggingFaceHub(huggingfacehub_api_token=huggingfacehub_api_token, repo_id=repo_id, model_kwargs={"temperature":0.7, "max_new_tokens":500})

    template="""Question: {question}
    Answer: give me details and recommendation."""

    prompt = PromptTemplate(template=template, input_variables=["question"])
    chain = LLMChain(prompt=prompt,llm=llm)

    out = chain.run(description)
    out=out.split('\n')

    solution=' '.join(out[2:])
    return solution

def call_api(keyword):
    url='https://services.nvd.nist.gov/rest/json/cves/2.0'
    data={
        'keywordSearch':keyword,
        'resultsPerPage':1
    }
    response=requests.get(url=url,data=data).json()['vulnerabilities']
    return response

def extract_last_column(line):
    parts = line.split()
    return ' '.join(parts[4:])

def read_scanned_file(file_path):
    keywords=[]
    with open(file_path, 'r') as file:
        for line in file:
            if not line.startswith('+'):
                keyword = extract_last_column(line).strip()
                if len(keyword)!=0:
                    keywords.append(keyword)

    responses=[]
    for keyword in keywords:
        response = call_api(keyword)
        if len(response)!=0:
            result=dict()
            descriptions=response[0]['cve']['descriptions'][0]['value']
            solution= chatbot_api(descriptions)
            result['keyword']=keyword
            result['descriptions']=descriptions
            result['solution']=solution
            responses.append(result)
            
    savejson(responses)

file_path = '/results.txt'
read_scanned_file(file_path)

FROM python:3

COPY . /app
WORKDIR /app

RUN pip install -i https://pypi.tuna.tsinghua.edu.cn/simple -r requirements.txt

EXPOSE 10001

ENV ROOT_PATH ""

CMD exec uvicorn api:app --host 0.0.0.0 --port 10001 --root-path $ROOT_PATH

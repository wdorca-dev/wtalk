FROM gcc:latest

WORKDIR /app

COPY . .

RUN g++ -std=c++17 Talk-Server-Linux-Plain.cpp -pthread -o talkserver

EXPOSE 8888

CMD ["./talkserver"]

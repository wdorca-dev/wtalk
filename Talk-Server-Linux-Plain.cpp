// Talk-Server-Linux-Plain.cpp
// Linux test version: plain-text accounts, no DPAPI, no BCrypt, no encryption.
// Build: g++ -std=c++17 Talk-Server-Linux-Plain.cpp -pthread -o talkserver
// Run:   ./talkserver
// Protocol:
//   SIGNUP_PLAIN|username|password
//   LOGIN_PLAIN|username|password
// After login, any sent text is broadcast as "username: text".

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <iostream>
#include <map>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using namespace std;

using Socket = int;

static const int PORT = 8888;
static const char* ACCOUNT_FILE = "accounts.txt";

vector<Socket> clients;
map<Socket, string> clientNames;
mutex clientsMutex;

static void SendToken(Socket clientSocket, const string& token)
{
    send(clientSocket, token.c_str(), token.size(), 0);
}

static vector<string> Split(const string& s, char delimiter)
{
    vector<string> parts;
    string item;
    stringstream ss(s);

    while (getline(ss, item, delimiter))
        parts.push_back(item);

    return parts;
}

static bool IsValidName(const string& name)
{
    if (name.empty() || name.size() > 32)
        return false;

    for (char c : name)
    {
        if (!(isalnum((unsigned char)c) || c == '_' || c == '-'))
            return false;
    }

    return true;
}

static bool LoadAccountPassword(const string& name, string& password)
{
    password.clear();

    ifstream fin(ACCOUNT_FILE);
    if (!fin.is_open())
        return false;

    string line;
    while (getline(fin, line))
    {
        size_t p = line.find('|');
        if (p == string::npos)
            continue;

        string user = line.substr(0, p);
        string pass = line.substr(p + 1);

        if (user == name)
        {
            password = pass;
            return true;
        }
    }

    return false;
}

static bool AccountExists(const string& name)
{
    string tmp;
    return LoadAccountPassword(name, tmp);
}

static bool SaveAccountPassword(const string& name, const string& password)
{
    if (!IsValidName(name) || password.empty() || password.find('\n') != string::npos || password.find('|') != string::npos)
        return false;

    vector<string> lines;
    {
        ifstream fin(ACCOUNT_FILE);
        string line;

        while (getline(fin, line))
        {
            size_t p = line.find('|');
            if (p == string::npos)
                continue;

            string user = line.substr(0, p);
            if (user != name)
                lines.push_back(line);
        }
    }

    lines.push_back(name + "|" + password);

    ofstream fout(ACCOUNT_FILE, ios::trunc);
    if (!fout.is_open())
        return false;

    for (const string& line : lines)
        fout << line << "\n";

    return true;
}

static void CreateDefaultAccountIfMissing()
{
    if (!AccountExists("user"))
    {
        if (SaveAccountPassword("user", "pass"))
            cout << "created default account: user / pass" << endl;
        else
            cout << "failed to create default account" << endl;
    }
}

static bool ParseAuthPacket(const string& msg, const string& type, string& name, string& password)
{
    const string prefix = type + "|";
    if (msg.rfind(prefix, 0) != 0)
        return false;

    vector<string> parts = Split(msg, '|');
    if (parts.size() != 3)
        return false;

    name = parts[1];
    password = parts[2];

    return IsValidName(name) && !password.empty();
}

static bool HandleSignup(Socket clientSocket, const string& msg)
{
    string name;
    string password;

    if (!ParseAuthPacket(msg, "SIGNUP_PLAIN", name, password))
    {
        SendToken(clientSocket, "SIGNUP_FAILED");
        return false;
    }

    if (AccountExists(name))
    {
        cout << "signup failed, account exists: " << name << endl;
        SendToken(clientSocket, "SIGNUP_FAILED");
        return false;
    }

    if (!SaveAccountPassword(name, password))
    {
        cout << "signup save failed: " << name << endl;
        SendToken(clientSocket, "SIGNUP_FAILED");
        return false;
    }

    {
        lock_guard<mutex> lock(clientsMutex);
        clientNames[clientSocket] = name;
    }

    SendToken(clientSocket, "SIGNUP_SUCCESS");
    cout << "signup success: " << name << endl;
    return true;
}

static bool HandleLogin(Socket clientSocket, const string& msg)
{
    string name;
    string password;

    if (!ParseAuthPacket(msg, "LOGIN_PLAIN", name, password))
    {
        SendToken(clientSocket, "LOGIN_FAILED");
        return false;
    }

    string correctPassword;
    if (!LoadAccountPassword(name, correctPassword) || password != correctPassword)
    {
        SendToken(clientSocket, "LOGIN_FAILED");
        cout << "login failed: " << name << endl;
        return false;
    }

    {
        lock_guard<mutex> lock(clientsMutex);
        clientNames[clientSocket] = name;
    }

    SendToken(clientSocket, "LOGIN_SUCCESS");
    cout << "login success: " << name << endl;
    return true;
}

static void BroadcastMessage(const string& msg)
{
    lock_guard<mutex> lock(clientsMutex);

    for (Socket client : clients)
        send(client, msg.c_str(), msg.size(), 0);
}

static void RemoveClient(Socket clientSocket)
{
    lock_guard<mutex> lock(clientsMutex);

    clients.erase(remove(clients.begin(), clients.end(), clientSocket), clients.end());
    clientNames.erase(clientSocket);
}

static void HandleClient(Socket clientSocket)
{
    char buffer[2048];
    bool loggedIn = false;

    while (true)
    {
        int bytes = recv(clientSocket, buffer, sizeof(buffer) - 1, 0);

        if (bytes == 0)
        {
            cout << "client disconnected" << endl;
            break;
        }

        if (bytes < 0)
        {
            cout << "recv failed: " << strerror(errno) << endl;
            break;
        }

        buffer[bytes] = '\0';
        string msg = buffer;

        // Remove common trailing CR/LF from terminal clients like nc.
        while (!msg.empty() && (msg.back() == '\n' || msg.back() == '\r'))
            msg.pop_back();

        if (!loggedIn)
        {
            if (msg.rfind("SIGNUP_PLAIN|", 0) == 0)
                loggedIn = HandleSignup(clientSocket, msg);
            else if (msg.rfind("LOGIN_PLAIN|", 0) == 0)
                loggedIn = HandleLogin(clientSocket, msg);
            else
            {
                SendToken(clientSocket, "LOGIN_FAILED");
                cout << "unknown auth packet: [" << msg << "]" << endl;
                break;
            }

            if (!loggedIn)
                break;

            continue;
        }

        string name;
        {
            lock_guard<mutex> lock(clientsMutex);
            name = clientNames[clientSocket];
        }

        string fullMsg = name + ": " + msg;
        cout << "received: " << fullMsg << endl;
        BroadcastMessage(fullMsg);
    }

    RemoveClient(clientSocket);
    close(clientSocket);
}

int main()
{
    CreateDefaultAccountIfMissing();

    Socket serverSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (serverSocket < 0)
    {
        cout << "socket failed: " << strerror(errno) << endl;
        return 1;
    }

    int opt = 1;
    setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_addr.s_addr = INADDR_ANY;
    serverAddr.sin_port = htons(PORT);

    if (bind(serverSocket, reinterpret_cast<sockaddr*>(&serverAddr), sizeof(serverAddr)) < 0)
    {
        cout << "bind failed: " << strerror(errno) << endl;
        close(serverSocket);
        return 1;
    }

    if (listen(serverSocket, SOMAXCONN) < 0)
    {
        cout << "listen failed: " << strerror(errno) << endl;
        close(serverSocket);
        return 1;
    }

    cout << "Server started on port " << PORT << endl;

    while (true)
    {
        Socket clientSocket = accept(serverSocket, nullptr, nullptr);

        if (clientSocket < 0)
        {
            cout << "accept failed: " << strerror(errno) << endl;
            continue;
        }

        {
            lock_guard<mutex> lock(clientsMutex);
            clients.push_back(clientSocket);
        }

        cout << "client connected" << endl;
        thread t(HandleClient, clientSocket);
        t.detach();
    }

    close(serverSocket);
    return 0;
}

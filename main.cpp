#include <bits/stdc++.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <syslog.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <signal.h>

#include <boost/algorithm/string.hpp>

using namespace std;

mode_t getumask(void)
{
    mode_t m = umask(0);
    umask(m);
    return m;
}

enum class logLevel
{
    INFO,
    ERROR,
    LOG
};

string logLevelToString(const logLevel &log);

string logLevelToString(const logLevel &log)
{
    if (log == logLevel::INFO)
        return "INFO";
    else if (log == logLevel::ERROR)
    {
        return "ERROR";
    }
    else if (log == logLevel::LOG)
    {
        return "LOG";
    }
    return "";
}


class TintinReporter
{
public:

    TintinReporter()
    {
        _fd = open("/var/mattlog/log", O_CREAT |O_APPEND| O_RDWR, 0644);
        if (_fd == -1)
        {
            cout << "cannot openned log file" << endl;
        }
    }

    ~TintinReporter()
    {
        if (islogFileOpened())
            close(_fd);
    }

    bool islogFileOpened() const
    {
        return (_fd != -1);
    }

    void write(const string &str, const logLevel &log)
    {
        if (islogFileOpened() == false)
            return ;
        string line;
        time_t rawtime;
        struct tm *info;
        char buffer[80];
        time(&rawtime);
        info = localtime(&rawtime);
        strftime(buffer,80,"[%d/%m/%Y-%H:%M:%S] [ ", info);
        line += buffer;
        line += logLevelToString(log);
        line += " ] - ";
        line += str;
        line += '\n';
        ::write(_fd, line.c_str() , line.size());
    }

    int _fd;
    const string _logFile = "/var/mattlog/log";
};

TintinReporter _tintin;

class Server
{
public:

    Server() : _loop(true)
    {

    }

    ~Server()
    {
        for (int i : fds)
        {
            _tintin.write(string("close fd: ") + to_string(i), logLevel::INFO);
            close(i);
        }
    }

    bool initServer()
    {
        if (_tintin.islogFileOpened() == false)
            return false;
        struct sockaddr_in my_addr;
        _socketFd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        _tintin.write("Socket fd: " + to_string(_socketFd), logLevel::INFO);
        if (_socketFd == -1)
        {
            _tintin.write("Error Socket", logLevel::ERROR);
            return false;
        }
        _tintin.write("Socket Ready", logLevel::INFO);
        my_addr.sin_family = AF_INET;
        my_addr.sin_port = htons(_port);
        my_addr.sin_addr.s_addr = INADDR_ANY;
        bzero(&(my_addr.sin_zero), 8);
        int ret = ::bind(_socketFd, (struct sockaddr *)&my_addr, sizeof(struct sockaddr));
        if (ret == -1)
        {
            _tintin.write("Error Bind", logLevel::ERROR);
            return false;
        }
        _tintin.write("Bind Success", logLevel::INFO);
        if (listen (_socketFd, 3) < 0)
        {
            _tintin.write("Error listen", logLevel::ERROR);
            return false;
        }
        _tintin.write("Server is listening", logLevel::INFO);
        return true;
    }

    int readFromClient(int fd)
    {
        char buffer[2000] = {0};
        int nbytes;

         nbytes = read (fd, buffer, 2000);
         if (nbytes < 0)
         {
             _tintin.write("Client Read ERROR", logLevel::ERROR);
             return -1;
         }
         else if (nbytes == 0)
         {
             _tintin.write("Client has disconnected", logLevel::INFO);
             return -1;
         }
         else
         {
             buffer[nbytes] = 0;
             string msg = buffer;
             boost::trim_right(msg);
             _tintin.write(msg, logLevel::LOG);
             if (msg == "quit")
                 _loop = false;
             return 0;
         }
    }

    void stopLoop()
    {
        _loop = false;
    }


    void start()
    {
        int i;
        struct timeval tv;
        struct sockaddr_in client;
        socklen_t sizeClient;
        int highestFd = _socketFd;
        FD_ZERO (&_readSet);
        FD_SET (_socketFd, &_readSet);
        _tintin.write("start Select", logLevel::INFO);
        while (_loop)
        {
            FD_ZERO (&_readSet);
            FD_SET (_socketFd, &_readSet);
            for (int i : fds)
            {
                FD_SET (i, &_readSet);
            }

            tv.tv_sec = 5;
            tv.tv_usec = 0;
            if (select (highestFd + 1, &_readSet, NULL, NULL, &tv/* NULL */) < 0)
            {
                _tintin.write(string("Error Select: ") + string(strerror(errno)), logLevel::ERROR);
                _loop = false;
                break;
            }
            //_tintin.write("End Select", logLevel::INFO);
            for (i = 0; i < highestFd + 1; ++i)
            {
                if (FD_ISSET (i, &_readSet))
                {
                    if (i == _socketFd)
                    {
                        //_tintin.write("New Connection", logLevel::INFO);
                        int newFd;
                        sizeClient = sizeof (client);
                        newFd = ::accept(_socketFd,(struct sockaddr *) &client, &sizeClient);
                        if (newFd < 0)
                        {
                            _tintin.write("Accept Error", logLevel::ERROR);
                            return ;
                        }
                        if (fds.size() >= 3)
                        {
                            close (newFd);
                        }
                        else
                        {
                            _tintin.write(string("New Client from ") + string(inet_ntoa (client.sin_addr))
                                          + " " + to_string(ntohs(client.sin_port))  , logLevel::INFO);
                            FD_SET (newFd, &_readSet);
                            highestFd = max(newFd, highestFd);
                            fds.push_back(newFd);
                        }

                    }
                    else
                    {
                        // msg from client
                        if (readFromClient(i) < 0)
                        {
                            // si le client est parti
                            close (i);
                            auto it = find(fds.begin(), fds.end(), i);
                            if (it != fds.end())
                            {
                               fds.erase(it);
                            }

                            FD_CLR (i, &_readSet);
                        }
                    }
                }
            }
        }
    }

    vector<int> fds;
    fd_set _readSet;
    const short _port = 4242;
    int _socketFd;
    bool _loop;

};

Server server;

void onSignalReceived(int signal)
{
    if (signal == SIGTERM || signal == SIGINT || signal == SIGSEGV)
    {
        _tintin.write(string("Signal: ") + to_string(signal) + string(" received") , logLevel::INFO);
        server.stopLoop();
    }
}


int main()
{
    if(geteuid() != 0)
    {
        cout << "root needed" << endl;
        return 0;
    }
    umask(0);
    int fdLock = open ("/var/lock/mattLock",  O_CREAT, 0644);
    if (fdLock == -1)
    {
        _tintin.write("Open /var/lock/mattLock failed", logLevel::ERROR);
        return 0;
    }

    if (flock(fdLock, LOCK_EX | LOCK_NB) == -1)
    {
        _tintin.write("Cannot lock file", logLevel::ERROR);
        cerr << "Cannot lock file" << endl;
        close(fdLock);
        return 0;
    }


    server.initServer();


    signal(SIGTERM, &onSignalReceived);
    signal(SIGINT, &onSignalReceived);
    signal(SIGSEGV, &onSignalReceived);

    pid_t pid, sid;

    pid = fork();
    if (pid < 0)
    {
       _tintin.write("Error fork", logLevel::ERROR);
       return 0;
    }
    if (pid > 0)
    {
        _tintin.write("fork1 parent finish", logLevel::INFO);
        return 0;
    }
    _tintin.write("child PID: " + to_string(getpid()), logLevel::INFO);
    sid = setsid();
    pid = fork();
    if (pid < 0)
    {
       _tintin.write("What's the fork2", logLevel::ERROR);
       return 0;
    }
    if (pid > 0)
    {
        _tintin.write("fork2 parent finish", logLevel::INFO);
        return 0;
    }
    _tintin.write("Entering daemon mode", logLevel::INFO);
    _tintin.write("child PID: " + to_string(getpid()), logLevel::INFO);
    if (sid < 0)
    {
        _tintin.write("setsid Error", logLevel::ERROR);
        return 0;
    }

    if ((chdir("/var/lock")) < 0)
    {
        _tintin.write("Cannot change working directory", logLevel::ERROR);
        return 0;
    }
    _tintin.write("Change working directory to /var/lock", logLevel::INFO);
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    server.start();
    if (flock(fdLock, LOCK_UN) == -1)
    {
         _tintin.write("Error Unlocked", logLevel::ERROR);
         close(fdLock);
         return 0;
    }
    _tintin.write(string("Close fd socket: ") + to_string(fdLock), logLevel::INFO);
    close(fdLock);
    _tintin.write("Unlocked /var/lock/mattLock", logLevel::INFO);
    _tintin.write("Daemon Finished", logLevel::INFO);
    if (remove("/var/lock/mattLock") == 0)
    {
        _tintin.write("/var/lock/mattLock removed", logLevel::INFO);
    }
    else
    {
        _tintin.write("Error remove", logLevel::ERROR);
    }
    return 0;
}

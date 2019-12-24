#include <windows.h>


HINSTANCE	g_hInstance = NULL;


extern void DestroyMsgLoop();

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
        GetModuleHandleEx(0, NULL, &g_hInstance);
		//g_hInstance = GetModuleHandle(NULL);
		break;
	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case DLL_PROCESS_DETACH:
		DestroyMsgLoop();
		break;
	}
	return TRUE;
}
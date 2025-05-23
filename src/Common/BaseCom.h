/*
 Derived from source code of TrueCrypt 7.1a, which is
 Copyright (c) 2008-2012 TrueCrypt Developers Association and which is governed
 by the TrueCrypt License 3.0.

 Modifications and additions to the original source code (contained in this file) 
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages.
*/

#ifndef TC_HEADER_BASE_COM
#define TC_HEADER_BASE_COM

#include <guiddef.h>

template <class TClass>
class TrueCryptFactory : public IClassFactory
{

public:
	TrueCryptFactory (DWORD messageThreadId) : 
		RefCount (1), ServerLockCount (0), MessageThreadId (messageThreadId) { }

	~TrueCryptFactory () { }
	
	virtual ULONG STDMETHODCALLTYPE AddRef ()
	{
		return InterlockedIncrement (&RefCount) - 1;
	}

	virtual ULONG STDMETHODCALLTYPE Release ()
	{
		ULONG r = InterlockedDecrement (&RefCount) + 1;

		if (r == 0)
			delete this;

		return r;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface (REFIID riid, void **ppvObject)
	{
		if (riid == IID_IUnknown || riid == IID_IClassFactory)
			*ppvObject = this;
		else
		{
			*ppvObject = NULL;
			return E_NOINTERFACE;
		}

		AddRef ();
		return S_OK;
	}
        
	virtual HRESULT STDMETHODCALLTYPE CreateInstance (IUnknown *pUnkOuter, REFIID riid, void **ppvObject)
	{
		if (pUnkOuter != NULL)
			return CLASS_E_NOAGGREGATION;

		TClass *tc = new TClass (MessageThreadId);
		if (tc == NULL)
			return E_OUTOFMEMORY;

		HRESULT hr = tc->QueryInterface (riid, ppvObject);

		if (hr)
			delete tc;

		return hr;
	}

	virtual HRESULT STDMETHODCALLTYPE LockServer (BOOL fLock)
	{
		if (fLock)
		{
			InterlockedIncrement (&ServerLockCount);
		}
		else
		{
			if (!InterlockedDecrement (&ServerLockCount))
				PostThreadMessage (MessageThreadId, WM_APP, 0, 0);
		}

		return S_OK;
	}

	virtual bool IsServerLocked ()
	{
		return ServerLockCount > 0;
	}

protected:
	DWORD MessageThreadId;
	LONG RefCount;
	LONG ServerLockCount;
};


class BaseCom
{
public:
	static DWORD CallDriver (DWORD ioctl, BSTR input, BSTR *output);
	static DWORD CopyFile (BSTR sourceFile, BSTR destinationFile);
	static DWORD DeleteFile (BSTR file);
	static BOOL IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
	static DWORD ReadWriteFile (BOOL write, BOOL device, BSTR filePath, BSTR *bufferBstr, unsigned __int64 offset, unsigned __int32 size, DWORD *sizeDone);
	static DWORD RegisterFilterDriver (BOOL registerDriver, int filterType);
	static DWORD RegisterSystemFavoritesService (BOOL registerService);
	static DWORD SetDriverServiceStartType (DWORD startType);
	static DWORD WriteLocalMachineRegistryDwordValue (BSTR keyPath, BSTR valueName, DWORD value);
	static DWORD GetFileSize (BSTR filePath, unsigned __int64 *pSize);
	static DWORD DeviceIoControl (BOOL readOnly, BOOL device, BSTR filePath, DWORD dwIoControlCode, BSTR input, BSTR *output);
	static DWORD InstallEfiBootLoader (BOOL preserveUserConfig, BOOL hiddenOSCreation, int pim, int hashAlg);
	static DWORD BackupEfiSystemLoader ();
	static DWORD RestoreEfiSystemLoader ();
	static DWORD GetEfiBootDeviceNumber (BSTR* pSdn);
	static DWORD WriteEfiBootSectorUserConfig (DWORD userConfig, BSTR customUserMessage, int pim, int hashAlg);
	static DWORD UpdateSetupConfigFile (BOOL bForInstall);
	static DWORD GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded);
	static DWORD NotifyService (DWORD dwNotifyCode);
	static DWORD FastFileResize (BSTR filePath, __int64 fileSize);

};


BOOL ComGetInstanceBase (HWND hWnd, REFCLSID clsid, REFIID iid, void **tcServer);
HRESULT CreateElevatedComObject (HWND hwnd, REFGUID guid, REFIID iid, void **ppv);

#endif // TC_HEADER_BASE_COM

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

#ifndef TC_HEADER_Common_BootEncryption
#define TC_HEADER_Common_BootEncryption

#include "Tcdefs.h"
#include "Dlgcode.h"
#include "Exception.h"
#include "Platform/PlatformBase.h"
#include "Volumes.h"

typedef ULONG (WINAPI *RtlNtStatusToDosErrorFn)(
  NTSTATUS Status
);

using namespace std;

namespace VeraCrypt
{
	class File
	{
	public:
		File () : Elevated (false), FileOpen (false), ReadOnly (false), FilePointerPosition(0), Handle(INVALID_HANDLE_VALUE), IsDevice(false), LastError(0) { }
		File (wstring path,bool readOnly = false, bool create = false);
		virtual ~File () { Close(); }

		bool IsOpened () const { return FileOpen;}
		void CheckOpened (const char* srcPos) { if (!FileOpen) { SetLastError (LastError); throw SystemException (srcPos);} }
		void Close ();
		DWORD Read (uint8 *buffer, DWORD size);
		void Write (uint8 *buffer, DWORD size);
		void SeekAt (int64 position);
		void GetFileSize (unsigned __int64& size);
		void GetFileSize (DWORD& dwSize);
      bool IoCtl(DWORD code, void* inBuf, DWORD inBufSize, void* outBuf, DWORD outBufSize);

	protected:
		bool Elevated;
		bool FileOpen;
		bool ReadOnly;
		uint64 FilePointerPosition;
		HANDLE Handle;
		bool IsDevice;
		wstring Path;
		DWORD LastError;
		BYTE ReadBuffer[4096];
	};


	class Device : public File
	{
	public:
		Device (wstring path,bool readOnly = false);
		virtual ~Device () {}
	};


	class Buffer
	{
	public:
		Buffer (size_t size) : DataSize (size)
		{
			DataPtr = new uint8[size];
			if (!DataPtr)
				throw bad_alloc();
		}

		~Buffer () { delete[] DataPtr; }
		uint8 *Ptr () const { return DataPtr; }
		size_t Size () const { return DataSize; }
		void Resize (size_t newSize)
		{ 
			if (newSize > DataSize)
			{
				uint8 *tmp = new uint8[newSize];
				if (!tmp)
					throw bad_alloc();
				memcpy (tmp, DataPtr, DataSize);
				delete [] DataPtr;			
				DataPtr = tmp;
			}
			DataSize = newSize;
		}

	protected:
		uint8 *DataPtr;
		size_t DataSize;
	};


	struct Partition
	{
		wstring DevicePath;
		PARTITION_INFORMATION Info;
		wstring MountPoint;
		size_t Number;
		BOOL IsGPT;
		wstring VolumeNameId;
	};

	typedef list <Partition> PartitionList;

#pragma pack (push)
#pragma pack(1)

	struct PartitionEntryMBR
	{
		uint8 BootIndicator;

		uint8 StartHead;
		uint8 StartCylSector;
		uint8 StartCylinder;

		uint8 Type;

		uint8 EndHead;
		uint8 EndSector;
		uint8 EndCylinder;

		uint32 StartLBA;
		uint32 SectorCountLBA;
	};

	struct MBR
	{
		uint8 Code[446];
		PartitionEntryMBR Partitions[4];
		uint16 Signature;
	};

#pragma pack (pop)

	struct SystemDriveConfiguration
	{
		wstring DeviceKernelPath;
		wstring DevicePath;
		int DriveNumber;
		Partition DrivePartition;
		bool ExtraBootPartitionPresent;
		int64 InitialUnallocatedSpace;
		PartitionList Partitions;
		Partition SystemPartition;
		int64 TotalUnallocatedSpace;
		bool SystemLoaderPresent;
	};

	class EfiBootConf
	{
	public:

		int passwordType;
		string passwordMsg;
		string passwordPicture;
		string hashMsg;
		int hashAlgo;
		int requestHash;
		string pimMsg;
		int pim;
		int requestPim;
		int authorizeVisible;
		int authorizeRetry;
		int bmlLockFlags;
		int bmlDriverEnabled;
		string actionSuccessValue;

		EfiBootConf();

		static BOOL ReadConfigValue (char* configContent, const char *configKey, char *configValue, int maxValueSize);
		static int ReadConfigInteger (char* configContent, const char *configKey, int defaultValue);
		static char *ReadConfigString (char* configContent, const char *configKey, char *defaultValue, char *str, int maxLen);
		static BOOL WriteConfigString (FILE* configFile, char* configContent, const char *configKey, const char *configValue);
		static BOOL WriteConfigInteger (FILE* configFile, char* configContent, const char *configKey, int configValue);
		BOOL Load (const wchar_t* fileName);
		void Load (char* configContent);
		BOOL Save (const wchar_t* fileName, HWND hwnd);
		static BOOL IsPostExecFileField (const string& szFieldValue, string& filePath);
		static BOOL IsPostExecFileField (const string& szFieldValue, wstring& filePath);
	};

	void GetVolumeESP(wstring& path, wstring& bootVolumePath);
	std::string ReadESPFile (LPCWSTR szFilePath, bool bSkipUTF8BOM);
	void WriteESPFile (LPCWSTR szFilePath, LPBYTE pbData, DWORD dwDataLen, bool bAddUTF8BOM);

	class EfiBoot {
	public:
		EfiBoot();

		void PrepareBootPartition(bool bDisableException = false);
		bool IsEfiBoot();

		void DeleteStartExec(uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL);
		void SetStartExec(wstring description, wstring execPath, bool setBootEntry = true, bool forceFirstBootEntry = true, bool setBootNext = true, uint16 statrtOrderNum = 0xDC5B, wchar_t* type = NULL, uint32 attr = 1);
		void SaveFile(const wchar_t* name, uint8* data, DWORD size);
		void GetFileSize(const wchar_t* name, unsigned __int64& size);
		void ReadFile(const wchar_t* name, uint8* data, DWORD size);
		void CopyFile(const wchar_t* name, const wchar_t* targetName);
		bool FileExists(const wchar_t* name);
		static bool CompareFiles (const wchar_t* fileName1, const wchar_t* fileName2);
		static bool CompareFileData (const wchar_t* fileName, const uint8* data, DWORD size);

		BOOL RenameFile(const wchar_t* name, const wchar_t* nameNew, BOOL bForce);
		BOOL DelFile(const wchar_t* name);
		BOOL MkDir(const wchar_t* name, bool& bAlreadyExists);
		BOOL ReadConfig (const wchar_t* name, EfiBootConf& conf);
		BOOL UpdateConfig (const wchar_t* name, int pim, int hashAlgo, HWND hwndDlg);
		BOOL WriteConfig (const wchar_t* name, bool preserveUserConfig, int pim, int hashAlgo, const char* passPromptMsg, HWND hwndDlg);
		BOOL DelDir(const wchar_t* name);
		PSTORAGE_DEVICE_NUMBER GetStorageDeviceNumber () { if (bDeviceInfoValid) return &sdn; else { SetLastError (ERROR_INVALID_DRIVE); throw SystemException(SRC_POS);}}

	protected:
		bool m_bMounted;
		std::wstring	EfiBootPartPath;
		STORAGE_DEVICE_NUMBER sdn;
		PARTITION_INFORMATION_EX partInfo;
		bool bDeviceInfoValid;
		WCHAR     tempBuf[1024];
		std::wstring BootVolumePath;
	};

	class BootEncryption
	{
	public:
		BootEncryption (HWND parent, bool postOOBE = false, bool setBootEntry = true, bool forceFirstBootEntry = true, bool setBootNext = false);
		~BootEncryption ();

		enum FilterType
		{
			DriveFilter,
			VolumeFilter,
			DumpFilter
		};

		void SetParentWindow (HWND parent) { ParentWindow = parent; }
		void AbortDecoyOSWipe ();
		void AbortSetup ();
		void AbortSetupWait ();
		void CallDriver (DWORD ioctl, void *input = nullptr, DWORD inputSize = 0, void *output = nullptr, DWORD outputSize = 0);
		int ChangePassword (Password *oldPassword, int old_pkcs5, int old_pim, Password *newPassword, int pkcs5, int pim, int wipePassCount, HWND hwndDlg);
		void CheckDecoyOSWipeResult ();
		void CheckEncryptionSetupResult ();
		void CheckRequirements ();
		void CheckRequirementsHiddenOS ();
		void CopyFileAdmin (const wstring &sourceFile, const wstring &destinationFile);
		void CreateRescueIsoImage (bool initialSetup, const wstring &isoImagePath);
		void Deinstall (bool displayWaitDialog = false);
		void DeleteFileAdmin (const wstring &file);
		DecoySystemWipeStatus GetDecoyOSWipeStatus ();
		DWORD GetDriverServiceStartType ();
		unsigned int GetHiddenOSCreationPhase ();
		uint16 GetInstalledBootLoaderVersion ();
		void GetInstalledBootLoaderFingerprint (uint8 fingerprint[WHIRLPOOL_DIGESTSIZE + SHA512_DIGESTSIZE]);
		Partition GetPartitionForHiddenOS ();
		bool IsBootLoaderOnDrive (wchar_t *devicePath);
		BootEncryptionStatus GetStatus ();
		void GetVolumeProperties (VOLUME_PROPERTIES_STRUCT *properties);
		SystemDriveConfiguration GetSystemDriveConfiguration ();
		void Install (bool hiddenSystem, int hashAlgo);
		void InstallBootLoader (Device& device, bool preserveUserConfig = false, bool hiddenOSCreation = false, int pim = -1, int hashAlg = -1);
		void InstallBootLoader (bool preserveUserConfig = false, bool hiddenOSCreation = false, int pim = -1, int hashAlg = -1);
		bool CheckBootloaderFingerprint (bool bSilent = false);
		void InvalidateCachedSysDriveProperties ();
		bool IsCDRecorderPresent ();
		bool IsHiddenSystemRunning ();
		bool IsPagingFileActive (BOOL checkNonWindowsPartitionsOnly);
		void PrepareHiddenOSCreation (int ea, int mode, int pkcs5);
		void PrepareInstallation (bool systemPartitionOnly, Password &password, int ea, int mode, int pkcs5, int pim, const wstring &rescueIsoImagePath);
		void ProbeRealSystemDriveSize ();
		bool ReadBootSectorConfig (uint8 *config, size_t bufLength, uint8 *userConfig = nullptr, string *customUserMessage = nullptr, uint16 *bootLoaderVersion = nullptr);
		uint32 ReadDriverConfigurationFlags ();
		uint32 ReadServiceConfigurationFlags ();
		void RegisterBootDriver (bool hiddenSystem);
		void RegisterFilterDriver (bool registerDriver, FilterType filterType);
		void RegisterSystemFavoritesService (BOOL registerService);
		void RegisterSystemFavoritesService (BOOL registerService, BOOL noFileHandling);
		bool IsSystemFavoritesServiceRunning ();
		void UpdateSystemFavoritesService ();
		void RenameDeprecatedSystemLoaderBackup ();
		bool RestartComputer (BOOL bShutdown = FALSE);
		void InitialSecurityChecksForHiddenOS ();
		void RestrictPagingFilesToSystemPartition ();
		void SetDriverConfigurationFlag (uint32 flag, bool state);
		void SetServiceConfigurationFlag (uint32 flag, bool state);
		void SetDriverServiceStartType (DWORD startType);
		void SetHiddenOSCreationPhase (unsigned int newPhase);
		void StartDecryption (BOOL discardUnreadableEncryptedSectors);
		void StartDecoyOSWipe (WipeAlgorithmId wipeAlgorithm);
		void StartEncryption (WipeAlgorithmId wipeAlgorithm, bool zeroUnreadableSectors);
		bool SystemDriveContainsPartitionType (uint8 type);
		bool SystemDriveContainsExtendedPartition ();
		bool SystemDriveContainsNonStandardPartitions ();
		bool SystemPartitionCoversWholeDrive ();
		bool SystemDriveIsDynamic ();
		bool VerifyRescueDisk ();
		bool VerifyRescueDiskImage (const wchar_t* imageFile);
		void WipeHiddenOSCreationConfig ();
		void WriteBootDriveSector (uint64 offset, uint8 *data);
		void WriteBootSectorConfig (const uint8 newConfig[]);
		void WriteBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg);
		void WriteEfiBootSectorUserConfig (uint8 userConfig, const string &customUserMessage, int pim, int hashAlg);
		void WriteLocalMachineRegistryDwordValue (wchar_t *keyPath, wchar_t *valueName, DWORD value);
		void GetEfiBootDeviceNumber (PSTORAGE_DEVICE_NUMBER pSdn);
		void BackupSystemLoader ();
		void RestoreSystemLoader ();
		static void UpdateSetupConfigFile (bool bForInstall);
		void GetSecureBootConfig (BOOL* pSecureBootEnabled, BOOL *pVeraCryptKeysLoaded);
		bool IsUsingUnsupportedAlgorithm(LONG driverVersion);
		void NotifyService (DWORD dwNotifyCmd);
	protected:
		static const uint32 RescueIsoImageSize = 1835008; // Size of ISO9660 image with bootable emulated 1.44MB floppy disk image

		void CreateBootLoaderInMemory (uint8 *buffer, size_t bufferSize, bool rescueDisk, bool hiddenOSCreation = false);
		void CreateVolumeHeader (uint64 volumeSize, uint64 encryptedAreaStart, Password *password, int ea, int mode, int pkcs5, int pim);
		wstring GetSystemLoaderBackupPath ();
		uint32 GetChecksum (uint8 *data, size_t size);
		DISK_GEOMETRY_EX GetDriveGeometry (int driveNumber);
		PartitionList GetDrivePartitions (int driveNumber);
		wstring GetRemarksOnHiddenOS ();
		wstring GetWindowsDirectory ();
		void RegisterFilter (bool registerFilter, FilterType filterType, const GUID *deviceClassGuid = nullptr);		
		void InstallVolumeHeader ();

		HWND ParentWindow;
		SystemDriveConfiguration DriveConfig;
		int SelectedEncryptionAlgorithmId;
		int SelectedPrfAlgorithmId;
		Partition HiddenOSCandidatePartition;
		uint8 *RescueIsoImage;
		uint8 *RescueZipData;
		unsigned long RescueZipSize;
		uint8 RescueVolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		uint8 VolumeHeader[TC_BOOT_ENCRYPTION_VOLUME_HEADER_SIZE];
		bool DriveConfigValid;
		bool RealSystemDriveSizeValid;
		bool RescueVolumeHeaderValid;
		bool VolumeHeaderValid;
		bool PostOOBEMode;
		bool SetBootNext;
		bool SetBootEntry;
		bool ForceFirstBootEntry;
	};
}

#define TC_ABORT_TRANSFORM_WAIT_INTERVAL	10

#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_NTFS	2.1
#define MIN_HIDDENOS_DECOY_PARTITION_SIZE_RATIO_FAT		1.05

#define TC_SYS_BOOT_LOADER_BACKUP_NAME			L"Original System Loader"
#define TC_SYS_BOOT_LOADER_BACKUP_NAME_LEGACY	L"Original System Loader.bak"	// Deprecated to prevent removal by some "cleaners"

#define TC_SYSTEM_FAVORITES_SERVICE_NAME				_T(TC_APP_NAME) L"SystemFavorites"
#define	TC_SYSTEM_FAVORITES_SERVICE_LOAD_ORDER_GROUP	L"Event Log"
#define TC_SYSTEM_FAVORITES_SERVICE_CMDLINE_OPTION		L"/systemFavoritesService"
#define VC_SYSTEM_FAVORITES_SERVICE_ARG_SKIP_MOUNT		L"/SkipMount"
#define VC_SYSTEM_FAVORITES_SERVICE_ARG_UPDATE_LOADER	L"/UpdateLoader"

#define VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_UPDATE_LOADER			0x1
#define VC_SYSTEM_FAVORITES_SERVICE_CONFIG_FORCE_SET_BOOTNEXT			0x2
#define VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_SET_BOOTENTRY			0x4
#define VC_SYSTEM_FAVORITES_SERVICE_CONFIG_DONT_FORCE_FIRST_BOOTENTRY	0x8

#define VC_WINDOWS_UPGRADE_POSTOOBE_CMDLINE_OPTION		L"/PostOOBE"

#endif // TC_HEADER_Common_BootEncryption

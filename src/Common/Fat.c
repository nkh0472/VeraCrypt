/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of TrueCrypt 7.1a, which is
 Copyright (c) 2003-2012 TrueCrypt Developers Association and which is
 governed by the TrueCrypt License 3.0, also from the source code of
 Encryption for the Masses 2.02a, which is Copyright (c) 1998-2000 Paul Le Roux
 and which is governed by the 'License Agreement for Encryption for the Masses'
 Modifications and additions to the original source code (contained in this file)
 and all other portions of this file are Copyright (c) 2013-2025 AM Crypto
 and are governed by the Apache License 2.0 the full text of which is
 contained in the file License.txt included in VeraCrypt binary and source
 code distribution packages. */

#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "Tcdefs.h"

#include "Crypto.h"
#include "Common/Endian.h"
#include "Format.h"
#include "Fat.h"
#include "Progress.h"
#include "Random.h"
#include "Volumes.h"
#include "Dlgcode.h"

void
GetFatParams (fatparams * ft)
{
	uint64 volumeSize = (uint64) ft->num_sectors * ft->sector_size;
	unsigned int fatsecs;

	if(ft->cluster_size == 0)	// 'Default' cluster size
	{
		uint32 clusterSize;

		// Determine optimal cluster size to minimize FAT size (mounting delay), maximize number of files, keep 4 KB alignment, etc.
		if (volumeSize >= 2 * BYTES_PER_TB)
			clusterSize = 256 * BYTES_PER_KB;
		else if (volumeSize >= 512 * BYTES_PER_GB)
			clusterSize = 128 * BYTES_PER_KB;
		else if (volumeSize >= 128 * BYTES_PER_GB)
			clusterSize = 64 * BYTES_PER_KB;
		else if (volumeSize >= 64 * BYTES_PER_GB)
			clusterSize = 32 * BYTES_PER_KB;
		else if (volumeSize >= 32 * BYTES_PER_GB)
			clusterSize = 16 * BYTES_PER_KB;
		else if (volumeSize >= 16 * BYTES_PER_GB)
			clusterSize = 8 * BYTES_PER_KB;
		else if (volumeSize >= 512 * BYTES_PER_MB)
			clusterSize = 4 * BYTES_PER_KB;
		else if (volumeSize >= 256 * BYTES_PER_MB)
			clusterSize = 2 * BYTES_PER_KB;
		else if (volumeSize >= 1 * BYTES_PER_MB)
			clusterSize = 1 * BYTES_PER_KB;
		else
			clusterSize = 512;

		ft->cluster_size = clusterSize / ft->sector_size;

		if (ft->cluster_size == 0)
			ft->cluster_size = 1;

		if (((unsigned __int64) ft->cluster_size * ft->sector_size) > TC_MAX_FAT_CLUSTER_SIZE)
			ft->cluster_size = TC_MAX_FAT_CLUSTER_SIZE / ft->sector_size;

		if (ft->cluster_size > 128)
			ft->cluster_size = 128;
	}

	if (volumeSize <= TC_MAX_FAT_CLUSTER_SIZE * 4)
		ft->cluster_size = 1;

	// Geometry always set to SECTORS/1/1
	ft->secs_track = 1;
	ft->heads = 1;

	ft->dir_entries = 512;
	ft->fats = 2;
	ft->media = 0xf8;
	ft->hidden = 0;

	ft->size_root_dir = ft->dir_entries * 32;

	// FAT12
	ft->size_fat = 12;
	ft->reserved = 2;
	fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
	ft->cluster_count = (int) (((unsigned __int64) fatsecs * ft->sector_size) / ((unsigned __int64) ft->cluster_size * ft->sector_size));
	ft->fat_length = (((ft->cluster_count * 3 + 1) >> 1) + ft->sector_size - 1) / ft->sector_size;

	if (ft->cluster_count >= 4085) // FAT16
	{
		ft->size_fat = 16;
		ft->reserved = 2;
		fatsecs = ft->num_sectors - (ft->size_root_dir + ft->sector_size - 1) / ft->sector_size - ft->reserved;
		ft->cluster_count = (int) (((__int64) fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
		ft->fat_length = (ft->cluster_count * 2 + ft->sector_size - 1) / ft->sector_size;
	}

	if(ft->cluster_count >= 65525) // FAT32
	{
		ft->size_fat = 32;
		ft->reserved = 32 - 1;

		do
		{
			ft->reserved++;

			fatsecs = ft->num_sectors - ft->reserved;
			ft->size_root_dir = ft->cluster_size * ft->sector_size;
			ft->cluster_count = (int) (((unsigned __int64) fatsecs * ft->sector_size) / (ft->cluster_size * ft->sector_size));
			ft->fat_length = (ft->cluster_count * 4 + ft->sector_size - 1) / ft->sector_size;

		// Align data area on TC_MAX_VOLUME_SECTOR_SIZE

		} while (ft->sector_size == TC_SECTOR_SIZE_LEGACY
				&& (ft->reserved * ft->sector_size + ft->fat_length * ft->fats * ft->sector_size) % TC_MAX_VOLUME_SECTOR_SIZE != 0);
	}

	ft->cluster_count -= ft->fat_length * ft->fats / ft->cluster_size;

	if (ft->num_sectors >= 65536 || ft->size_fat == 32)
	{
		ft->sectors = 0;
		ft->total_sect = ft->num_sectors;
	}
	else
	{
		ft->sectors = (uint16) ft->num_sectors;
		ft->total_sect = 0;
	}
}

void
PutBoot (fatparams * ft, unsigned char *boot)
{
	int cnt = 0;

	boot[cnt++] = 0xeb;	/* boot jump */
	boot[cnt++] = (ft->size_fat == 32)? 0x58: 0x3c;
	boot[cnt++] = 0x90;
	memcpy (boot + cnt, "MSDOS5.0", 8); /* system id */
	cnt += 8;
	*(__int16 *)(boot + cnt) = LE16(ft->sector_size);	/* bytes per sector */
	cnt += 2;
	boot[cnt++] = (__int8) ft->cluster_size;			/* sectors per cluster */
	*(__int16 *)(boot + cnt) = LE16(ft->reserved);		/* reserved sectors */
	cnt += 2;
	boot[cnt++] = (__int8) ft->fats;					/* 2 fats */

	if(ft->size_fat == 32)
	{
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
	}
	else
	{
		*(__int16 *)(boot + cnt) = LE16(ft->dir_entries);	/* 512 root entries */
		cnt += 2;
	}

	*(__int16 *)(boot + cnt) = LE16(ft->sectors);		/* # sectors */
	cnt += 2;
	boot[cnt++] = (__int8) ft->media;					/* media byte */

	if(ft->size_fat == 32)
	{
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
	}
	else
	{
		*(__int16 *)(boot + cnt) = LE16((uint16) ft->fat_length);	/* fat size */
		cnt += 2;
	}

	*(__int16 *)(boot + cnt) = LE16(ft->secs_track);	/* # sectors per track */
	cnt += 2;
	*(__int16 *)(boot + cnt) = LE16(ft->heads);			/* # heads */
	cnt += 2;
	*(__int32 *)(boot + cnt) = LE32(ft->hidden);		/* # hidden sectors */
	cnt += 4;
	*(__int32 *)(boot + cnt) = LE32(ft->total_sect);	/* # huge sectors */
	cnt += 4;

	if(ft->size_fat == 32)
	{
		*(__int32 *)(boot + cnt) = LE32(ft->fat_length); cnt += 4;	/* fat size 32 */
		boot[cnt++] = 0x00;	/* ExtFlags */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;	/* FSVer */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x02;	/* RootClus */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x01;	/* FSInfo */
		boot[cnt++] = 0x00;
		boot[cnt++] = 0x06;	/* BkBootSec */
		boot[cnt++] = 0x00;
		memset(boot+cnt, 0, 12); cnt+=12;	/* Reserved */
	}

	boot[cnt++] = 0x00;	/* drive number */   // FIXED 80 > 00
	boot[cnt++] = 0x00;	/* reserved */
	boot[cnt++] = 0x29;	/* boot sig */

	memcpy (boot + cnt, ft->volume_id, 4);		/* vol id */
	cnt += 4;

	memcpy (boot + cnt, ft->volume_name, 11);	/* vol title */
	cnt += 11;

	switch(ft->size_fat) /* filesystem type */
	{
		case 12: memcpy (boot + cnt, "FAT12   ", 8); break;
		case 16: memcpy (boot + cnt, "FAT16   ", 8); break;
		case 32: memcpy (boot + cnt, "FAT32   ", 8); break;
	}
	cnt += 8;

	memset (boot + cnt, 0, ft->size_fat==32 ? 420:448);	/* boot code */
	cnt += ft->size_fat==32 ? 420:448;
	boot[cnt++] = 0x55;
	boot[cnt++] = 0xaa;	/* boot sig */
}


/* FAT32 FSInfo */
static void PutFSInfo (unsigned char *sector, fatparams *ft)
{
	memset (sector, 0, ft->sector_size);
	sector[3]=0x41; /* LeadSig */
	sector[2]=0x61;
	sector[1]=0x52;
	sector[0]=0x52;
	sector[484+3]=0x61; /* StrucSig */
	sector[484+2]=0x41;
	sector[484+1]=0x72;
	sector[484+0]=0x72;

	// Free cluster count
	*(uint32 *)(sector + 488) = LE32 (ft->cluster_count - ft->size_root_dir / ft->sector_size / ft->cluster_size);

	// Next free cluster
	*(uint32 *)(sector + 492) = LE32 (2);

	sector[508+3]=0xaa; /* TrailSig */
	sector[508+2]=0x55;
	sector[508+1]=0x00;
	sector[508+0]=0x00;
}


int
FormatFat (void* hwndDlgPtr, unsigned __int64 startSector, fatparams * ft, void * dev, PCRYPTO_INFO cryptoInfo, volatile void *volParamsArg)
{
	int write_buf_cnt = 0;
	char sector[TC_MAX_VOLUME_SECTOR_SIZE], *write_buf;
	unsigned __int64 nSecNo = startSector;
	unsigned __int64 nSkipSectors = 128 * (unsigned __int64) BYTES_PER_MB / ft->sector_size;
	unsigned __int64 num_sectors;
	DWORD bytesWritten;
	int x, n;
	int retVal;
	CRYPTOPP_ALIGN_DATA(16) char temporaryKey[MASTER_KEYDATA_SIZE];
	HWND hwndDlg = (HWND) hwndDlgPtr;
	volatile FORMAT_VOL_PARAMETERS* volParams = (volatile FORMAT_VOL_PARAMETERS*)volParamsArg;
	BOOL quickFormat = volParams->quickFormat;
	BOOL bDevice = volParams->bDevice;

	LARGE_INTEGER startOffset;
	LARGE_INTEGER newOffset;

	// Seek to start sector
	startOffset.QuadPart = startSector * ft->sector_size;
	if (!SetFilePointerEx ((HANDLE) dev, startOffset, &newOffset, FILE_BEGIN)
		|| newOffset.QuadPart != startOffset.QuadPart)
	{
		return ERR_VOL_SEEKING;
	}

	/* Write the data area */

	write_buf = (char *)TCalloc (FormatWriteBufferSize);
	if (!write_buf)
		return ERR_OUTOFMEMORY;

	memset (sector, 0, ft->sector_size);

	if (!RandgetBytes (hwndDlg, ft->volume_id, sizeof (ft->volume_id), FALSE))
		goto fail;

	PutBoot (ft, (unsigned char *) sector);
	if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
		cryptoInfo, volParams) == FALSE)
		goto fail;

	/* fat32 boot area */
	if (ft->size_fat == 32)
	{
		/* fsinfo */
		PutFSInfo((unsigned char *) sector, ft);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
			cryptoInfo, volParams) == FALSE)
			goto fail;

		/* reserved */
		while (nSecNo - startSector < 6)
		{
			memset (sector, 0, ft->sector_size);
			sector[508+3]=0xaa; /* TrailSig */
			sector[508+2]=0x55;
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				cryptoInfo, volParams) == FALSE)
				goto fail;
		}

		/* bootsector backup */
		memset (sector, 0, ft->sector_size);
		PutBoot (ft, (unsigned char *) sector);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				 cryptoInfo, volParams) == FALSE)
			goto fail;

		PutFSInfo((unsigned char *) sector, ft);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
			cryptoInfo, volParams) == FALSE)
			goto fail;
	}

	/* reserved */
	while (nSecNo - startSector < (unsigned int)ft->reserved)
	{
		memset (sector, 0, ft->sector_size);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
			cryptoInfo, volParams) == FALSE)
			goto fail;
	}

	/* write fat */
	for (x = 1; x <= ft->fats; x++)
	{
		for (n = 0; n < ft->fat_length; n++)
		{
			memset (sector, 0, ft->sector_size);

			if (n == 0)
			{
				unsigned char fat_sig[12];
				if (ft->size_fat == 32)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = fat_sig[2] = 0xff;
					fat_sig[3] = 0x0f;
					fat_sig[4] = fat_sig[5] = fat_sig[6] = 0xff;
					fat_sig[7] = 0x0f;
					fat_sig[8] = fat_sig[9] = fat_sig[10] = 0xff;
					fat_sig[11] = 0x0f;
					memcpy (sector, fat_sig, 12);
				}
				else if (ft->size_fat == 16)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0xff;
					memcpy (sector, fat_sig, 4);
				}
				else if (ft->size_fat == 12)
				{
					fat_sig[0] = (unsigned char) ft->media;
					fat_sig[1] = 0xff;
					fat_sig[2] = 0xff;
					fat_sig[3] = 0x00;
					memcpy (sector, fat_sig, 4);
				}
			}

			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				    cryptoInfo, volParams) == FALSE)
				goto fail;
		}
	}


	/* write rootdir */
	for (x = 0; x < ft->size_root_dir / ft->sector_size; x++)
	{
		memset (sector, 0, ft->sector_size);
		if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				 cryptoInfo, volParams) == FALSE)
			goto fail;

	}

	/* Fill the rest of the data area with random data */

	if(!quickFormat)
	{
		CRYPTO_INFO tmpCI;

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;

		/* Generate a random temporary key set to be used for "dummy" encryption that will fill
		the free disk space (data area) with random data.  This is necessary for plausible
		deniability of hidden volumes (and also reduces the amount of predictable plaintext
		within the volume). */

		VirtualLock (&tmpCI, sizeof (tmpCI));
		memcpy (&tmpCI, cryptoInfo, sizeof (CRYPTO_INFO));
		cryptoInfo = &tmpCI;

		// Temporary master key
		if (!RandgetBytes (hwndDlg, temporaryKey, EAGetKeySize (cryptoInfo->ea), FALSE))
		{
			burn (&tmpCI, sizeof (tmpCI));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
			goto fail;
		}

		// Temporary secondary key (XTS mode)
		if (!RandgetBytes (hwndDlg, cryptoInfo->k2, sizeof cryptoInfo->k2, FALSE))
		{
			burn (&tmpCI, sizeof (tmpCI));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
			goto fail;
		}

		retVal = EAInit (cryptoInfo->ea, temporaryKey, cryptoInfo->ks);
		if (retVal != ERR_SUCCESS)
		{
			TCfree (write_buf);
			burn (temporaryKey, sizeof(temporaryKey));
			burn (&tmpCI, sizeof (tmpCI));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
			return retVal;
		}
		if (!EAInitMode (cryptoInfo, cryptoInfo->k2))
		{
			TCfree (write_buf);
			burn (temporaryKey, sizeof(temporaryKey));
			burn (&tmpCI, sizeof (tmpCI));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
			return ERR_MODE_INIT_FAILED;
		}

		if (IsRamEncryptionEnabled ())
			VcProtectKeys (cryptoInfo, VcGetEncryptionID (cryptoInfo));

		x = ft->num_sectors - ft->reserved - ft->size_root_dir / ft->sector_size - ft->fat_length * 2;
		while (x--)
		{
			if (WriteSector (dev, sector, write_buf, &write_buf_cnt, &nSecNo, startSector,
				cryptoInfo, volParams) == FALSE)
				goto fail;
		}

		if (volParams->progress_callback)
		{
			// Call the progress callback function if it is set
			volParams->progress_callback ((nSecNo - startSector) * ft->sector_size, volParams->progress_callback_user_data);
		}
		else
		{
			UpdateProgressBar ((nSecNo - startSector) * ft->sector_size);
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
		{
			burn (&tmpCI, sizeof (tmpCI));
			VirtualUnlock (&tmpCI, sizeof (tmpCI));
			goto fail;
		}

		burn (&tmpCI, sizeof (tmpCI));
		VirtualUnlock (&tmpCI, sizeof (tmpCI));
	}
	else if (!bDevice)
	{
		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;

		// Quick format: write a zeroed sector every 128 MiB, leaving other sectors untouched
		// This helps users visualize the progress of actual file creation while forcing Windows
		// to allocate the disk space of each 128 MiB chunk immediately, otherwise, Windows 
		// would delay the allocation until we write the backup header at the end of the volume which
		// would make the user think that the format process has stalled after progress bar reaches 100%.
		num_sectors = ft->num_sectors - ft->reserved - ft->size_root_dir / ft->sector_size - ft->fat_length * 2;
		while (num_sectors >= nSkipSectors)
		{
			// seek to next sector to be written
			nSecNo += (nSkipSectors - 1);
			startOffset.QuadPart = nSecNo * ft->sector_size;
			if (!MoveFilePointer ((HANDLE) dev, startOffset))
			{
				goto fail;
			}
			
			// sector array has been zeroed above
			if (!WriteFile ((HANDLE) dev, sector, ft->sector_size, &bytesWritten, NULL) 
				|| bytesWritten != ft->sector_size)
			{
				goto fail;
			}
			
			nSecNo++;
			num_sectors -= nSkipSectors;

			if (volParams->progress_callback)
			{
				// Call the progress callback function if it is set
				if (!volParams->progress_callback ((nSecNo - startSector) * ft->sector_size, volParams->progress_callback_user_data))
				{
					goto fail;
				}
			}
			else
			{
				if (UpdateProgressBar ((nSecNo - startSector)* ft->sector_size))
					goto fail;
		   }
			
		}
		
		nSecNo += num_sectors;
		if (volParams->progress_callback)
	 	{
			// Call the progress callback function if it is set
			volParams->progress_callback ((nSecNo - startSector) * ft->sector_size, volParams->progress_callback_user_data);
		}
		else
		{
			UpdateProgressBar ((nSecNo - startSector)* ft->sector_size);
		}
	}
	else
	{
		if (volParams->progress_callback)
		{
			// Call the progress callback function if it is set
			volParams->progress_callback ((uint64) ft->num_sectors * ft->sector_size, volParams->progress_callback_user_data);
		}
		else
		{
			UpdateProgressBar ((uint64) ft->num_sectors * ft->sector_size);
		}

		if (!FlushFormatWriteBuffer (dev, write_buf, &write_buf_cnt, &nSecNo, cryptoInfo))
			goto fail;
	}

	TCfree (write_buf);
	burn (temporaryKey, sizeof(temporaryKey));
	return 0;

fail:

	TCfree (write_buf);
	burn (temporaryKey, sizeof(temporaryKey));
	return ERR_OS_ERROR;
}

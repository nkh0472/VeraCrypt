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

#ifndef TC_HEADER_Crypto_Aes_Hw_Cpu
#define TC_HEADER_Crypto_Aes_Hw_Cpu

#include "Common/Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#if defined (TC_WINDOWS_BOOT)
uint8 is_aes_hw_cpu_supported ();
void aes_hw_cpu_enable_sse ();
#endif
void aes_hw_cpu_decrypt (const uint8 *ks, uint8 *data);
void VC_CDECL aes_hw_cpu_decrypt_32_blocks (const uint8 *ks, uint8 *data);
void aes_hw_cpu_encrypt (const uint8 *ks, uint8 *data);
void VC_CDECL aes_hw_cpu_encrypt_32_blocks (const uint8 *ks, uint8 *data);

#if defined(__cplusplus)
}
#endif

#endif // TC_HEADER_Crypto_Aes_Hw_Cpu

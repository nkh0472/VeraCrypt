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

#ifdef __cplusplus
extern "C" {
#endif

void InitProgressBar (void);
BOOL UpdateProgressBarProc (int nPercent);
void RefreshUIGFX (void);
void localcleanupwiz (void);

BOOL CALLBACK PageDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );
BOOL CALLBACK MainDialogProc ( HWND hwndDlg , UINT uMsg , WPARAM wParam , LPARAM lParam );

extern BOOL bPromptTutorial;
extern BOOL bPromptReleaseNotes;
extern BOOL bPromptFastStartup;

#ifdef __cplusplus
}
#endif

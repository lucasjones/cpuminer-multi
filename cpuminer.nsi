; NSIS script (UTF-8) NSIS-3 Unicode
; Install

Unicode true
; SetCompressor lzma
RequestExecutionLevel Admin

; --------------------

!include FileFunc.nsh
!include WinMessages.nsh

AllowRootDirInstall true

; --------------------
; LANG TABLES: 1

!define MINER_VERSION "1.1"
!define VERSION "${MINER_VERSION}.0.0"

BrandingText "CPU Miner Install System"

!define PROGRAM_NAME "cpuminer-multi"
!define PROGRAM_KEY  "cpuminer"

Name "cpuminer-multi v${MINER_VERSION}"
OutFile "${PROGRAM_KEY}.exe"
Icon "res\setup.ico"
; Icon "res\${PROGRAM_KEY}.ico"
Caption "${PROGRAM_NAME}"

!define NSIS_MAKENSIS64

VIProductVersion ${VERSION}
VIAddVersionKey ProductName "${PROGRAM_NAME} - Setup"
VIAddVersionKey Comments ""
VIAddVersionKey CompanyName "Open Source"
VIAddVersionKey LegalCopyright "2015 - Open Source"
VIAddVersionKey FileDescription "${PROGRAM_NAME} - Setup"
VIAddVersionKey FileVersion ${MINER_VERSION}
VIAddVersionKey ProductVersion ${MINER_VERSION}
VIAddVersionKey InternalName ${PROGRAM_NAME}
VIAddVersionKey LegalTrademarks ""
VIAddVersionKey OriginalFilename "${PROGRAM_KEY}.exe"

!ifdef NSIS_MAKENSIS64
  !define BITS 64
  InstallDir $PROGRAMFILES64\cpuminer-multi
  !define RK_UNINSTALL "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_KEY}"
!else
  !define BITS 32
  InstallDir $PROGRAMFILES32\cpuminer-multi
  !define RK_UNINSTALL "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_KEY}"
  ;!define RK_UNINSTALL "SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\${PROGRAM_KEY}"
!endif

; InstType "Custom"

; LANG: ${LANG_ENGLISH}
LangString LSTR_0 ${LANG_ENGLISH} "CPU Miner Install System"
LangString LSTR_3 ${LANG_ENGLISH} "Space available: "
LangString LSTR_4 ${LANG_ENGLISH} "Space required: "
LangString LSTR_5 ${LANG_ENGLISH} "Can't write: "
LangString LSTR_17 ${LANG_ENGLISH} "Error decompressing data! Corrupted installer?"
LangString LSTR_21 ${LANG_ENGLISH} "Extract: "
LangString LSTR_22 ${LANG_ENGLISH} "Extract: error writing to file "
LangString LSTR_25 ${LANG_ENGLISH} "Output folder: "
LangString LSTR_29 ${LANG_ENGLISH} "Skipped: "
LangString LSTR_30 ${LANG_ENGLISH} "Copy Details To Clipboard"
LangString LSTR_32 ${LANG_ENGLISH} "B"
LangString LSTR_33 ${LANG_ENGLISH} "K"
LangString LSTR_34 ${LANG_ENGLISH} "M"
LangString LSTR_35 ${LANG_ENGLISH} "G"
LangString LSTR_36 ${LANG_ENGLISH} "Choose Install Location"
LangString LSTR_37 ${LANG_ENGLISH} "Choose the folder in which to install ${PROGRAM_NAME}."
LangString LSTR_38 ${LANG_ENGLISH} "Installing"
LangString LSTR_39 ${LANG_ENGLISH} "Please wait while ${PROGRAM_NAME} is being installed."
LangString LSTR_40 ${LANG_ENGLISH} "Installation Complete"
LangString LSTR_41 ${LANG_ENGLISH} "Setup was completed successfully."
LangString LSTR_42 ${LANG_ENGLISH} "Installation Aborted"
LangString LSTR_43 ${LANG_ENGLISH} "Setup was not completed successfully."
LangString LSTR_44 ${LANG_ENGLISH} "MS Shell Dlg"
LangString LSTR_45 ${LANG_ENGLISH} "8"
LangString LSTR_46 ${LANG_ENGLISH} "Error opening file for writing: $\r$\n$\r$\n$0$\r$\n$\r$\nClick Abort to stop the installation,$\r$\nRetry to try again, or$\r$\nIgnore to skip this file."
LangString LSTR_48 ${LANG_ENGLISH} "Cancel"
LangString LSTR_49 ${LANG_ENGLISH} "Setup will install ${PROGRAM_NAME} in the following folder. To install in a different folder, click Browse and select another folder. $_CLICK"
LangString LSTR_50 ${LANG_ENGLISH} "Destination Folder"
LangString LSTR_51 ${LANG_ENGLISH} "B&rowse..."
LangString LSTR_52 ${LANG_ENGLISH} "Select the folder to install ${PROGRAM_NAME} in:"
LangString LSTR_53 ${LANG_ENGLISH} "< &Back"
LangString LSTR_54 ${LANG_ENGLISH} "&Install"
LangString LSTR_55 ${LANG_ENGLISH} "Click Install to start the installation."
LangString LSTR_56 ${LANG_ENGLISH} "Show &details"
LangString LSTR_57 ${LANG_ENGLISH} "Completed"
LangString LSTR_58 ${LANG_ENGLISH} "&Next >"
LangString LSTR_59 ${LANG_ENGLISH} "Click Next to continue."
LangString LSTR_60 ${LANG_ENGLISH} " "
LangString LSTR_61 ${LANG_ENGLISH} "&Close"


; --------------------
; VARIABLES: 20

Var _0_
Var _1_
Var _2_
Var _3_
Var _4_
Var _5_
Var _6_
Var _7_
Var _8_
Var _9_
Var _10_
Var _11_
Var _12_
Var _13_
Var _14_
Var _15_
Var _16_
Var _17_
Var _18_
Var _19_


; --------------------
; PAGES: 3

; Page 0
Page directory func_2 func_5 func_13 /ENABLECANCEL
;  DirVar $CMDLINE
  DirText $(LSTR_49) $(LSTR_50) $(LSTR_51) $(LSTR_52)    ;  Setup will install ${PROGRAM_NAME} in the following folder....

; Page 1
Page instfiles func_14 func_17 func_23
  CompletedText $(LSTR_57)    ;  Completed
  DetailsButtonText $(LSTR_56)    ;  Show &details

/*
; Page 2
Page COMPLETED
*/


; --------------------

Function func_2    ; Page 0, Pre
  SendMessage $_0_ ${WM_SETTEXT} 0 STR:$(LSTR_36)    ;  Choose Install Location
  SendMessage $_2_ ${WM_SETTEXT} 0 STR:$(LSTR_37)    ;  Choose the folder in which to install ${PROGRAM_NAME}.
FunctionEnd


Function func_5    ; Page 0, Show
  FindWindow $_12_ "#32770" "" $HWNDPARENT
  GetDlgItem $_13_ $_12_ 1006
  GetDlgItem $_14_ $_12_ 1020
  GetDlgItem $_15_ $_12_ 1019
  GetDlgItem $_16_ $_12_ 1001
  GetDlgItem $_17_ $_12_ 1023
  GetDlgItem $_18_ $_12_ 1024
FunctionEnd


Function func_13    ; Page 0, Leave
FunctionEnd


Function func_14    ; Page 1, Pre
  SendMessage $_0_ ${WM_SETTEXT} 0 STR:$(LSTR_38)    ;  Installing
  SendMessage $_2_ ${WM_SETTEXT} 0 STR:$(LSTR_39)    ;  Please wait while ${PROGRAM_NAME} is being installed. cpuminer-multi
FunctionEnd


Function func_17    ; Page 1, Show
  FindWindow $_19_ "#32770" "" $HWNDPARENT
;  GetDlgItem $_20_ $_19_ 1006
;  GetDlgItem $_21_ $_19_ 1004
;  GetDlgItem $_22_ $_19_ 1027
;  GetDlgItem $_23_ $_19_ 1016
FunctionEnd


Function func_23    ; Page 1, Leave
  IfAbort label_27
  SendMessage $_0_ ${WM_SETTEXT} 0 STR:$(LSTR_40)    ;  "Installation Complete"
  SendMessage $_2_ ${WM_SETTEXT} 0 STR:$(LSTR_41)    ;  "Setup was completed successfully."
  Goto label_29
label_27:
  SendMessage $_0_ ${WM_SETTEXT} 0 STR:$(LSTR_42)    ;  "Installation Aborted"
  SendMessage $_2_ ${WM_SETTEXT} 0 STR:$(LSTR_43)    ;  "Setup was not completed successfully."
label_29:
  IfAbort label_30
label_30:
FunctionEnd

Function .onInit
  # `/SD IDYES' tells MessageBox to automatically choose IDYES if the installer is silent
  # in this case, the installer can only be silent if the user used the /S switch or if
  # you've uncommented line number 5
  # MessageBox MB_YESNO|MB_ICONQUESTION "Would you like the installer to be silent from now on?" \
  #  /SD IDYES IDNO no IDYES yes
  # yes:
  #   SetSilent silent
  #   Goto done
  # no:
  #   SetSilent normal

  #SetSilent silent

  ReadRegStr $R0 HKLM ${RK_UNINSTALL} \
    "UninstallString"
  StrCmp $R0 "" done

  DeleteRegKey HKLM ${RK_UNINSTALL}
  ClearErrors

done:

FunctionEnd


Function .onGUIInit
  GetDlgItem $_0_ $HWNDPARENT 1037
  CreateFont $_1_ $(LSTR_44) $(LSTR_45) 700    ;  "MS Shell Dlg" 8
  SendMessage $_0_ ${WM_SETFONT} $_1_ 0
  GetDlgItem $_2_ $HWNDPARENT 1038
  SetCtlColors $_0_ "" 0xFFFFFF
  SetCtlColors $_2_ "" 0xFFFFFF
  GetDlgItem $_3_ $HWNDPARENT 1034
  SetCtlColors $_3_ "" 0xFFFFFF
  GetDlgItem $_4_ $HWNDPARENT 1039
  SetCtlColors $_4_ "" 0xFFFFFF
  GetDlgItem $_6_ $HWNDPARENT 1028
  SetCtlColors $_6_ /BRANDING ""
  GetDlgItem $_5_ $HWNDPARENT 1256
  SetCtlColors $_5_ /BRANDING ""
  SendMessage $_5_ ${WM_SETTEXT} 0 "STR:$(LSTR_0) "    ;  "CPU Miner Install System"
  GetDlgItem $_7_ $HWNDPARENT 1035
  GetDlgItem $_8_ $HWNDPARENT 1045
  GetDlgItem $_9_ $HWNDPARENT 1
  GetDlgItem $_10_ $HWNDPARENT 2
  GetDlgItem $_11_ $HWNDPARENT 3
FunctionEnd


Function .onUserAbort
FunctionEnd


Section

  StrCmp $PROGRAMFILES32 $PROGRAMFILES +1
  SetRegView 32
  SetRegView 64

  SetOutPath $INSTDIR

  # call UserInfo plugin to get user info. The plugin puts the result in the stack
  UserInfo::getAccountType
  # pop the result from the stack into $0
  Pop $0

  # If match, jump 3 lines down.
  StrCmp $0 "Admin" +3
  MessageBox MB_OK "Installer requires admin rights: $0"
  Return

  SetOverwrite on
  ; File cpuminer-conf.json
  File cpuminer-gw64.exe
  File cpuminer-x64.exe
  ; File LICENCE
  ; File README.md

  SetOverwrite off
  AllowSkipFiles on
  File x64\Release\msvcr120.dll

  # Create the uninstaller
  WriteUninstaller "$INSTDIR\cpuminer-uninst.exe"

  # Shortcut for uninstaller
  # CreateShortCut "$SMPROGRAMS\Uninstall CPU Miner.lnk" "$INSTDIR\cpuminer-uninst.exe"

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "DisplayName" ${PROGRAM_NAME}

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "DisplayVersion" ${MINER_VERSION}

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "Publisher" "Open Source"

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "DisplayIcon" "$INSTDIR\cpuminer-x64.exe"

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "InstallLocation" "$\"$INSTDIR\$\""

  WriteRegStr HKLM ${RK_UNINSTALL} \
    "UninstallString" "$\"$INSTDIR\cpuminer-uninst.exe$\""

  ${GetSize} "$INSTDIR" "/M=cpuminer* /S=0K /G=0" $0 $1 $2
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD HKLM "${RK_UNINSTALL}" \
    "EstimatedSize" "$0"

SectionEnd


# uninstaller section start
Section "uninstall"

  Delete "$INSTDIR\cpuminer-conf.json"
  Delete "$INSTDIR\cpuminer-gw64.exe"
  Delete "$INSTDIR\cpuminer-x64.exe"
  StrCmp $INSTDIR "$WINDIR/system32" +1
  Delete "$INSTDIR\msvcr120.dll"

  Delete "$INSTDIR\cpuminer-uninst.exe"

  # second, remove the link from the start menu
  # Delete "$SMPROGRAMS\Uninstall CPU Miner.lnk"

  RMDir $INSTDIR
  DeleteRegKey HKLM ${RK_UNINSTALL}

# uninstaller section end
SectionEnd

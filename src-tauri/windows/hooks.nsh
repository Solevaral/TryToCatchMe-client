; NSIS hooks for the Tauri installer.

; The Start menu shortcut is created only on a fresh install by the Tauri template; after a reinstall
; over an existing copy (or if the user deleted it) the app stayed without one. Always make sure it exists.
!macro NSIS_HOOK_POSTINSTALL
  ${IfNot} ${FileExists} "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  ${EndIf}
!macroend

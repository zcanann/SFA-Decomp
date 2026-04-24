// Function: FUN_8022d5f0
// Entry: 8022d5f0
// Size: 68 bytes

void FUN_8022d5f0(int param_1)

{
  ushort uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  if (*(char *)(iVar2 + 0x470) == '\t') {
    *(short *)(iVar2 + 0x47c) = *(short *)(iVar2 + 0x47c) + 100;
    uVar1 = *(ushort *)(iVar2 + 0x47c);
    if (9999 < uVar1) {
      uVar1 = 9999;
    }
    *(ushort *)(iVar2 + 0x47c) = uVar1;
  }
  *(char *)(iVar2 + 0x470) = *(char *)(iVar2 + 0x470) + '\x01';
  return;
}


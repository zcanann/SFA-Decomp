// Function: FUN_8017ccfc
// Entry: 8017ccfc
// Size: 216 bytes

/* WARNING: Removing unreachable block (ram,0x8017cd48) */

undefined4 FUN_8017ccfc(int param_1,undefined4 param_2,int param_3)

{
  char cVar1;
  int iVar2;
  byte *pbVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x4c);
  pbVar3 = *(byte **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    cVar1 = *(char *)(param_3 + iVar2 + 0x81);
    if (cVar1 == '\x01') {
      FUN_800201ac((int)*(short *)(iVar4 + 0x18),1);
      FUN_8007d858();
    }
    else if (cVar1 == '\0') {
      FUN_800201ac((int)*(short *)(iVar4 + 0x1a),0);
      FUN_8007d858();
    }
  }
  *pbVar3 = *pbVar3 | 2;
  return 0;
}


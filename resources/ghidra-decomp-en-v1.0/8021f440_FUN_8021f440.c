// Function: FUN_8021f440
// Entry: 8021f440
// Size: 364 bytes

void FUN_8021f440(int param_1)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined auStack40 [4];
  undefined local_24 [3];
  char cStack33;
  undefined auStack32 [4];
  undefined auStack28 [4];
  undefined auStack24 [8];
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  if (((-1 < (char)*(byte *)(iVar4 + 0x19b)) && ((*(byte *)(iVar4 + 0x19b) >> 4 & 1) == 0)) &&
     (iVar1 = FUN_80036770(param_1,auStack40,0,local_24,auStack32,auStack28,auStack24), iVar1 == 5))
  {
    *(char *)(iVar4 + 0x19a) = *(char *)(iVar4 + 0x19a) - cStack33;
    FUN_80221e94((double)FLOAT_803e6b5c,param_1,auStack32);
    FUN_8009a8c8((double)FLOAT_803e6b60,param_1);
    if (*(char *)(iVar4 + 0x19a) < '\x01') {
      puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
      FUN_8009ab70((double)FLOAT_803e6b64,param_1,1,1,1,1,0,1,0);
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0x100;
      }
      *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0x7f | 0x80;
      FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
      if ((*(short *)(param_1 + 0x46) == 0x716) &&
         (iVar3 = FUN_80036e58(0x4c,param_1,0), iVar3 != 0)) {
        FUN_8023852c(iVar3,(int)*(short *)(iVar4 + 0x198));
      }
      else {
        FUN_80035f00(param_1);
      }
    }
  }
  return;
}


// Function: FUN_8021fa90
// Entry: 8021fa90
// Size: 364 bytes

void FUN_8021fa90(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)

{
  int iVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  undefined4 uStack_28;
  undefined4 local_24;
  float fStack_20;
  undefined4 uStack_1c;
  undefined4 auStack_18 [2];
  
  iVar4 = *(int *)(param_9 + 0xb8);
  iVar3 = *(int *)(param_9 + 0x4c);
  if (((-1 < (char)*(byte *)(iVar4 + 0x19b)) && ((*(byte *)(iVar4 + 0x19b) >> 4 & 1) == 0)) &&
     (iVar1 = FUN_80036868(param_9,&uStack_28,(int *)0x0,&local_24,&fStack_20,&uStack_1c,auStack_18)
     , iVar1 == 5)) {
    *(char *)(iVar4 + 0x19a) = *(char *)(iVar4 + 0x19a) - (char)local_24;
    FUN_802224e4(param_9,&fStack_20);
    FUN_8009ab54((double)FLOAT_803e77f8,param_9);
    if (*(char *)(iVar4 + 0x19a) < '\x01') {
      puVar2 = (undefined4 *)FUN_800395a4(param_9,0);
      FUN_8009adfc((double)FLOAT_803e77fc,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,1,1,1,1,0,1,0);
      if (puVar2 != (undefined4 *)0x0) {
        *puVar2 = 0x100;
      }
      *(byte *)(iVar4 + 0x19b) = *(byte *)(iVar4 + 0x19b) & 0x7f | 0x80;
      FUN_800201ac((int)*(short *)(iVar3 + 0x1e),1);
      if ((*(short *)(param_9 + 0x46) == 0x716) &&
         (iVar3 = FUN_80036f50(0x4c,param_9,(float *)0x0), iVar3 != 0)) {
        FUN_80238bf0(iVar3,(int)*(short *)(iVar4 + 0x198));
      }
      else {
        FUN_80035ff8(param_9);
      }
    }
  }
  return;
}


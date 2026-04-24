// Function: FUN_8018cacc
// Entry: 8018cacc
// Size: 568 bytes

void FUN_8018cacc(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 uint param_9)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar4;
  undefined2 *puVar5;
  double dVar6;
  uint uStack_18;
  uint local_14;
  
  iVar4 = *(int *)(param_9 + 0x4c);
  puVar5 = *(undefined2 **)(param_9 + 0xb8);
  iVar2 = FUN_8002bac4();
  if ((*(byte *)(puVar5 + 0x2e) >> 6 & 1) == 0) {
    if (((int)*(short *)(iVar4 + 0x1e) == 0xffffffff) ||
       (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x1e)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f;
        FUN_8000dbb0();
        FUN_8003709c(param_9,0x4f);
      }
    }
    else if (((int)*(short *)(iVar4 + 0x20) == 0xffffffff) ||
            (uVar3 = FUN_80020078((int)*(short *)(iVar4 + 0x20)), uVar3 != 0)) {
      if ((char)*(byte *)(puVar5 + 0x2e) < '\0') {
        if ((*(byte *)(puVar5 + 0x2e) >> 4 & 1) != 0) {
          *(undefined4 *)(param_9 + 0xc) = *(undefined4 *)(iVar4 + 8);
          *(undefined4 *)(param_9 + 0x10) = *(undefined4 *)(iVar4 + 0xc);
          *(undefined4 *)(param_9 + 0x14) = *(undefined4 *)(iVar4 + 0x10);
          *(undefined *)(param_9 + 0x36) = 0xff;
          *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xef;
        }
      }
      else {
        FUN_8000dcdc(param_9,0x403);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0x7f | 0x80;
        FUN_800372f8(param_9,0x4f);
      }
      fVar1 = *(float *)(param_9 + 0x10) - *(float *)(iVar2 + 0x10);
      if ((((FLOAT_803e49a0 < fVar1) && (fVar1 < FLOAT_803e49a4)) &&
          (uVar3 = FUN_80020078(0xe97), uVar3 == 0)) &&
         (dVar6 = FUN_80021730((float *)(param_9 + 0x18),(float *)(iVar2 + 0x18)),
         dVar6 < (double)FLOAT_803e49a8)) {
        *puVar5 = 0xcbe;
        FUN_800379bc(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,0x7000a,
                     param_9,(uint)puVar5,in_r7,in_r8,in_r9,in_r10);
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf | 0x40;
        FUN_800201ac(0xe97,1);
        FUN_8000bb38(param_9,0x49);
      }
    }
  }
  else {
    while (iVar2 = FUN_800375e4(param_9,&local_14,&uStack_18,(uint *)0x0), iVar2 != 0) {
      if (local_14 == 0x7000b) {
        *(byte *)(puVar5 + 0x2e) = *(byte *)(puVar5 + 0x2e) & 0xbf;
        FUN_800201ac((int)*(short *)(iVar4 + 0x1e),1);
        FUN_80020000(0x3f5);
        FUN_800201ac(0xe97,0);
      }
    }
  }
  return;
}


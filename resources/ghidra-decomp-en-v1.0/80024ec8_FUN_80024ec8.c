// Function: FUN_80024ec8
// Entry: 80024ec8
// Size: 1368 bytes

void FUN_80024ec8(int *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  char *local_48;
  undefined4 local_44;
  undefined auStack64 [4];
  char *local_3c;
  undefined4 local_38;
  undefined auStack52 [4];
  char *local_30;
  undefined4 local_2c;
  undefined auStack40 [4];
  char *local_24;
  undefined4 local_20;
  undefined auStack28 [12];
  
  *(undefined2 *)(param_2 + 0x44) = 0;
  *(undefined2 *)(param_2 + 0x5e) = 0;
  *(undefined2 *)(param_2 + 0x58) = 0;
  *(undefined2 *)(param_2 + 0x5a) = 0;
  *(undefined2 *)(param_2 + 0x5c) = 0;
  fVar1 = FLOAT_803de828;
  *(float *)(param_2 + 0xc) = FLOAT_803de828;
  *(float *)(param_2 + 4) = fVar1;
  *(float *)(param_2 + 0x14) = fVar1;
  *(undefined *)(param_2 + 0x60) = 0;
  iVar6 = *param_1;
  if (*(short *)(iVar6 + 0xec) != 0) {
    if ((*(ushort *)(iVar6 + 2) & 0x40) == 0) {
      iVar6 = *(int *)(*(int *)(iVar6 + 100) + (uint)*(ushort *)(param_2 + 0x44) * 4);
    }
    else {
      iVar3 = *(int *)(param_2 + 0x1c);
      iVar5 = (int)**(short **)(iVar6 + 0x6c);
      uVar2 = FUN_800430ac(0);
      if ((((uVar2 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar3 == 0) {
          iVar3 = FUN_80013c10(DAT_803dcb50,iVar5,&local_24);
          if (iVar3 == 0) {
            uVar4 = *(undefined4 *)(DAT_803dcb4c + iVar5 * 4);
            FUN_800464c8(0x30,0,uVar4,0,&local_20,iVar5,1);
            local_24 = (char *)FUN_80023cc8(local_20,10,0);
            FUN_800464c8(0x30,local_24,uVar4,local_20,auStack28,iVar5,0);
            *local_24 = '\x01';
            FUN_80013ce8(DAT_803dcb50,iVar5,&local_24);
          }
          else {
            *local_24 = *local_24 + '\x01';
          }
        }
        else {
          FUN_800280b4(iVar6,iVar5,0,iVar3);
        }
      }
      iVar5 = *(int *)(param_2 + 0x20);
      iVar3 = (int)**(short **)(iVar6 + 0x6c);
      uVar2 = FUN_800430ac(0);
      if ((((uVar2 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar5 == 0) {
          iVar5 = FUN_80013c10(DAT_803dcb50,iVar3,&local_30);
          if (iVar5 == 0) {
            uVar4 = *(undefined4 *)(DAT_803dcb4c + iVar3 * 4);
            FUN_800464c8(0x30,0,uVar4,0,&local_2c,iVar3,1);
            local_30 = (char *)FUN_80023cc8(local_2c,10,0);
            FUN_800464c8(0x30,local_30,uVar4,local_2c,auStack40,iVar3,0);
            *local_30 = '\x01';
            FUN_80013ce8(DAT_803dcb50,iVar3,&local_30);
          }
          else {
            *local_30 = *local_30 + '\x01';
          }
        }
        else {
          FUN_800280b4(iVar6,iVar3,0,iVar5);
        }
      }
      iVar5 = *(int *)(param_2 + 0x24);
      iVar3 = (int)**(short **)(iVar6 + 0x6c);
      uVar2 = FUN_800430ac(0);
      if ((((uVar2 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar5 == 0) {
          iVar5 = FUN_80013c10(DAT_803dcb50,iVar3,&local_3c);
          if (iVar5 == 0) {
            uVar4 = *(undefined4 *)(DAT_803dcb4c + iVar3 * 4);
            FUN_800464c8(0x30,0,uVar4,0,&local_38,iVar3,1);
            local_3c = (char *)FUN_80023cc8(local_38,10,0);
            FUN_800464c8(0x30,local_3c,uVar4,local_38,auStack52,iVar3,0);
            *local_3c = '\x01';
            FUN_80013ce8(DAT_803dcb50,iVar3,&local_3c);
          }
          else {
            *local_3c = *local_3c + '\x01';
          }
        }
        else {
          FUN_800280b4(iVar6,iVar3,0,iVar5);
        }
      }
      iVar5 = *(int *)(param_2 + 0x28);
      iVar3 = (int)**(short **)(iVar6 + 0x6c);
      uVar2 = FUN_800430ac(0);
      if ((((uVar2 & 0x100000) == 0) || (*(short *)(iVar6 + 4) == 1)) ||
         (*(short *)(iVar6 + 4) == 3)) {
        if (iVar5 == 0) {
          iVar6 = FUN_80013c10(DAT_803dcb50,iVar3,&local_48);
          if (iVar6 == 0) {
            uVar4 = *(undefined4 *)(DAT_803dcb4c + iVar3 * 4);
            FUN_800464c8(0x30,0,uVar4,0,&local_44,iVar3,1);
            local_48 = (char *)FUN_80023cc8(local_44,10,0);
            FUN_800464c8(0x30,local_48,uVar4,local_44,auStack64,iVar3,0);
            *local_48 = '\x01';
            FUN_80013ce8(DAT_803dcb50,iVar3,&local_48);
          }
          else {
            *local_48 = *local_48 + '\x01';
          }
        }
        else {
          FUN_800280b4(iVar6,iVar3,0,iVar5);
        }
      }
      *(undefined2 *)(param_2 + 0x44) = 0;
      iVar6 = *(int *)(param_2 + (uint)*(ushort *)(param_2 + 0x44) * 4 + 0x1c) + 0x80;
    }
    *(int *)(param_2 + 0x34) = iVar6 + 6;
    *(byte *)(param_2 + 0x60) = *(byte *)(iVar6 + 1) & 0xf0;
    *(float *)(param_2 + 0x14) =
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(*(int *)(param_2 + 0x34) + 1)) -
                DOUBLE_803de830);
    if (*(char *)(param_2 + 0x60) == '\0') {
      *(float *)(param_2 + 0x14) = *(float *)(param_2 + 0x14) - FLOAT_803de818;
    }
    *(undefined *)(param_2 + 0x61) = *(undefined *)(param_2 + 0x60);
    *(undefined4 *)(param_2 + 0x38) = *(undefined4 *)(param_2 + 0x34);
    *(undefined2 *)(param_2 + 0x46) = *(undefined2 *)(param_2 + 0x44);
    *(undefined4 *)(param_2 + 8) = *(undefined4 *)(param_2 + 4);
    *(undefined4 *)(param_2 + 0x18) = *(undefined4 *)(param_2 + 0x14);
    *(undefined4 *)(param_2 + 0x10) = *(undefined4 *)(param_2 + 0xc);
    *(undefined4 *)(param_2 + 0x3c) = *(undefined4 *)(param_2 + 0x34);
    *(undefined2 *)(param_2 + 0x48) = *(undefined2 *)(param_2 + 0x44);
    *(undefined4 *)(param_2 + 0x40) = *(undefined4 *)(param_2 + 0x34);
    *(undefined2 *)(param_2 + 0x4a) = *(undefined2 *)(param_2 + 0x44);
  }
  return;
}


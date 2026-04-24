// Function: FUN_8000be80
// Entry: 8000be80
// Size: 604 bytes

/* WARNING: Removing unreachable block (ram,0x8000c0b8) */

void FUN_8000be80(uint param_1,float *param_2,uint param_3,ushort param_4)

{
  bool bVar1;
  uint uVar2;
  ushort *puVar3;
  int iVar4;
  undefined uVar5;
  uint *puVar6;
  uint unaff_GQR0;
  double dVar7;
  double dVar8;
  uint local_50;
  ushort local_4c;
  byte local_4a [2];
  ushort local_48 [2];
  uint local_44;
  uint local_40;
  uint local_3c;
  float local_38;
  float local_34;
  float local_30;
  float afStack_2c [4];
  
  if ((unaff_GQR0 & 0x3f00) != 0) {
    ldexpf((byte)(unaff_GQR0 >> 8) & 0x3f);
  }
  bVar1 = false;
  local_50 = param_1;
  local_4c = param_4;
  uVar2 = FUN_8000c0dc(&local_50,&local_4c);
  if (uVar2 != 0) {
    puVar3 = FUN_8000c420((uint)local_4c);
    iVar4 = FUN_8000c1c8(puVar3,local_48,(char *)local_4a,&local_30,&local_34,&local_38,&local_3c,
                         &local_40,&local_44);
    if (iVar4 != 0) {
      if ((local_50 != 0) && (param_2 == (float *)0x0)) {
        param_2 = (float *)(local_50 + 0x18);
        bVar1 = true;
      }
      if (param_2 != (float *)0x0) {
        dVar8 = (double)local_38;
        dVar7 = FUN_8000cbe0(param_2,afStack_2c);
        if (dVar8 < dVar7) goto LAB_8000c0b8;
      }
      if ((param_3 & 0xff) != 0) {
        local_3c = param_3 & 0xff;
      }
      if ((local_50 == 0) || (local_3c == 0)) {
        if (local_4c == 0) {
          puVar6 = (uint *)0x0;
        }
        else {
          puVar6 = (uint *)FUN_8000cd0c(local_50,0,local_4c,1);
        }
        if ((puVar6 != (uint *)0x0) && ((local_40 != 0 || (DAT_803dd4bc == 3)))) {
          FUN_80272fcc(*puVar6);
          *puVar6 = 0xffffffff;
        }
      }
      else {
        if (((local_3c & 0xff) == 0) || (local_50 == 0)) {
          puVar6 = (uint *)0x0;
        }
        else {
          puVar6 = (uint *)FUN_8000cd0c(local_50,(ushort)(local_3c & 0xff),0,0);
        }
        if (puVar6 != (uint *)0x0) {
          if (local_40 == 0) goto LAB_8000c0b8;
          FUN_80272fcc(*puVar6);
          *puVar6 = 0xffffffff;
        }
      }
      puVar6 = (uint *)FUN_8000c4d8((uint)local_48[0],(uint)local_4a[0],0x40,local_44);
      if (puVar6 != (uint *)0x0) {
        *(ushort *)((int)puVar6 + 0x1e) = local_4c;
        *(short *)(puVar6 + 7) = (short)local_3c;
        puVar6[6] = local_50;
        if (param_2 == (float *)0x0) {
          *(undefined *)((int)puVar6 + 7) = 0x7f;
        }
        else {
          puVar6[8] = (uint)local_34;
          puVar6[9] = (uint)local_38;
          *(undefined *)(puVar6 + 1) = 1;
          uVar5 = 0;
          if ((bVar1) && (local_3c != 0)) {
            uVar5 = 1;
          }
          *(undefined *)((int)puVar6 + 5) = uVar5;
          puVar6[3] = (uint)*param_2;
          puVar6[4] = (uint)param_2[1];
          puVar6[5] = (uint)param_2[2];
          FUN_8000c6e0(puVar6);
        }
      }
    }
  }
LAB_8000c0b8:
  if ((unaff_GQR0 & 0x3f000000) != 0) {
    ldexpf(-((byte)(unaff_GQR0 >> 0x18) & 0x3f));
  }
  return;
}


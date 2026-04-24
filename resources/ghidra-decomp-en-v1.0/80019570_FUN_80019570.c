// Function: FUN_80019570
// Entry: 80019570
// Size: 660 bytes

ushort * FUN_80019570(uint param_1)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  ushort *puVar5;
  ushort *puVar6;
  
  fVar2 = FLOAT_803de704;
  if (*(int *)(DAT_803dc9ec + 0x1c) == 2) {
    puVar5 = *(ushort **)(DAT_803dc9ec + 4);
    for (iVar4 = *(int *)(DAT_803dc9ec + 0xc); iVar4 != 0; iVar4 = iVar4 + -1) {
      if (*puVar5 == param_1) {
        return puVar5;
      }
      puVar5 = puVar5 + 6;
    }
    iVar4 = 8;
    puVar5 = (ushort *)0x80339a20;
    do {
      puVar6 = puVar5;
      puVar5 = puVar6 + -6;
      bVar1 = iVar4 == 0;
      iVar4 = iVar4 + -1;
      if (bVar1) {
        DAT_803dc97c = DAT_803dc97c + 1;
        if (7 < DAT_803dc97c) {
          DAT_803dc97c = 0;
        }
        DAT_803dc974 = (ushort *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
        DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
        *DAT_803dc974 = 0xffff;
        DAT_803dc970 = (float *)(DAT_803dc97c * 4 + -0x7fcc6660);
        FUN_8028f688(DAT_803dc978,&DAT_803db3d4,param_1,(&PTR_s_Animtest_802c729c)[DAT_803dc9dc]);
        *DAT_803dc974 = (ushort)param_1;
        *DAT_803dc970 = FLOAT_803de704;
        return DAT_803dc974;
      }
    } while (*puVar5 != param_1);
    *(float *)(&DAT_80339980 + iVar4 * 4) = FLOAT_803de704;
    fVar3 = FLOAT_803de71c;
    if ((fVar2 < FLOAT_803de71c) &&
       (fVar2 = fVar2 + FLOAT_803db414, *(float *)(iVar4 * 4 + -0x7fcc6660) = fVar2, fVar3 <= fVar2)
       ) {
      FUN_8028f688(**(undefined4 **)(puVar6 + -2),s___d_s_not_in__s__802c9e3c,param_1,
                   (&PTR_s_Animtest_802c729c)[DAT_803dc9dc]);
    }
  }
  else {
    DAT_803dc97c = DAT_803dc97c + 1;
    if (7 < DAT_803dc97c) {
      DAT_803dc97c = 0;
    }
    DAT_803dc974 = (ushort *)(&DAT_803399c0 + DAT_803dc97c * 0xc);
    DAT_803dc978 = *(undefined4 *)(&DAT_803399c8)[DAT_803dc97c * 3];
    *DAT_803dc974 = 0xffff;
    DAT_803dc970 = (float *)(DAT_803dc97c * 4 + -0x7fcc6660);
    iVar4 = *(int *)(DAT_803dc9ec + 0x1c);
    puVar5 = DAT_803dc974;
    if (iVar4 != 2) {
      if (iVar4 < 2) {
        if (iVar4 == 0) {
          FUN_8028f688(DAT_803dc978,s__uninitialised__802c9e04);
          puVar5 = DAT_803dc974;
        }
        else if (-1 < iVar4) {
          FUN_8028f688(DAT_803dc978,s__loading__802c9e14);
          puVar5 = DAT_803dc974;
        }
      }
      else if (iVar4 == 4) {
        FUN_8028f688(DAT_803dc978,s__no_file___802c9e30);
        puVar5 = DAT_803dc974;
      }
      else if (iVar4 < 4) {
        FUN_8028f688(DAT_803dc978,s__file_empty___802c9e20);
        puVar5 = DAT_803dc974;
      }
    }
  }
  return puVar5;
}


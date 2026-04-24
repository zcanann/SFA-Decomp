// Function: FUN_802722b0
// Entry: 802722b0
// Size: 1040 bytes

void FUN_802722b0(uint param_1,uint param_2,uint param_3,undefined param_4,undefined4 param_5)

{
  float fVar1;
  uint uVar2;
  char cVar3;
  uint uVar4;
  float *pfVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  uint local_4c [3];
  undefined4 local_40;
  uint uStack_3c;
  
  local_4c[0] = param_2 & 0xffff;
  if (local_4c[0] != 0) {
    FUN_802836e4((int *)local_4c);
  }
  uVar4 = param_3 & 0xff;
  if (uVar4 == 0xfd) {
    cVar3 = '\0';
  }
  else if (uVar4 < 0xfd) {
    if (uVar4 == 0xfb) {
      cVar3 = '\x03';
    }
    else {
      if (0xfa < uVar4) {
        uStack_3c = param_1 & 0xff;
        pfVar5 = (float *)&DAT_803bdfc4;
        local_40 = 0x43300000;
        dVar9 = (double)FLOAT_803e8440;
        uVar4 = 0;
        dVar8 = (double)FLOAT_803e846c;
        dVar6 = (double)(FLOAT_803e8430 *
                        (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8458));
        dVar7 = DOUBLE_803e8458;
        do {
          if ((*(char *)((int)pfVar5 + 0x2d) == '\x02') || (*(char *)((int)pfVar5 + 0x2d) == '\x03')
             ) {
            *(undefined *)(pfVar5 + 0xb) = param_4;
            pfVar5[10] = -NAN;
            if (local_4c[0] == 0) {
              pfVar5[1] = (float)dVar6;
              *pfVar5 = (float)dVar6;
              if (pfVar5[10] != -NAN) {
                FUN_80271b90((int)pfVar5);
              }
            }
            else {
              uStack_3c = local_4c[0];
              local_40 = 0x43300000;
              pfVar5[2] = *pfVar5;
              pfVar5[1] = (float)dVar6;
              pfVar5[3] = (float)dVar9;
              pfVar5[4] = (float)(dVar8 / (double)(float)((double)CONCAT44(0x43300000,local_4c[0]) -
                                                         dVar7));
            }
            DAT_803deee0 = DAT_803deee0 | 1 << uVar4;
          }
          uVar4 = uVar4 + 1;
          pfVar5 = pfVar5 + 0xc;
        } while (uVar4 < 0x20);
        return;
      }
      if (uVar4 < 0xfa) goto LAB_802725c8;
      cVar3 = '\x02';
    }
  }
  else {
    if (uVar4 == 0xff) {
      uStack_3c = param_1 & 0xff;
      pfVar5 = (float *)&DAT_803bdfc4;
      local_40 = 0x43300000;
      dVar9 = (double)FLOAT_803e8440;
      uVar4 = 0;
      dVar8 = (double)FLOAT_803e846c;
      dVar6 = (double)(FLOAT_803e8430 *
                      (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8458));
      dVar7 = DOUBLE_803e8458;
      do {
        if ((*(char *)((int)pfVar5 + 0x2d) == '\0') || (*(char *)((int)pfVar5 + 0x2d) == '\x01')) {
          *(undefined *)(pfVar5 + 0xb) = param_4;
          pfVar5[10] = -NAN;
          if (local_4c[0] == 0) {
            pfVar5[1] = (float)dVar6;
            *pfVar5 = (float)dVar6;
            if (pfVar5[10] != -NAN) {
              FUN_80271b90((int)pfVar5);
            }
          }
          else {
            uStack_3c = local_4c[0];
            local_40 = 0x43300000;
            pfVar5[2] = *pfVar5;
            pfVar5[1] = (float)dVar6;
            pfVar5[3] = (float)dVar9;
            pfVar5[4] = (float)(dVar8 / (double)(float)((double)CONCAT44(0x43300000,local_4c[0]) -
                                                       dVar7));
          }
          DAT_803deee0 = DAT_803deee0 | 1 << uVar4;
        }
        uVar4 = uVar4 + 1;
        pfVar5 = pfVar5 + 0xc;
      } while (uVar4 < 0x20);
      return;
    }
    if (0xfe < uVar4) {
LAB_802725c8:
      uVar2 = param_3 & 0xff;
      (&DAT_803bdff0)[uVar2 * 0x30] = param_4;
      (&DAT_803bdfec)[uVar2 * 0xc] = param_5;
      if (local_4c[0] == 0) {
        local_4c[2] = param_1 & 0xff;
        local_4c[1] = 0x43300000;
        fVar1 = FLOAT_803e8430 * (float)((double)CONCAT44(0x43300000,local_4c[2]) - DOUBLE_803e8458)
        ;
        (&DAT_803bdfc8)[uVar2 * 0xc] = fVar1;
        (&DAT_803bdfc4)[uVar2 * 0xc] = fVar1;
        if ((&DAT_803bdfec)[uVar2 * 0xc] != -1) {
          FUN_80271b90((int)(&DAT_803bdfc4 + uVar2 * 0xc));
        }
      }
      else {
        (&DAT_803bdfcc)[uVar2 * 0xc] = (&DAT_803bdfc4)[uVar2 * 0xc];
        dVar7 = DOUBLE_803e8458;
        (&DAT_803bdfc8)[uVar2 * 0xc] =
             FLOAT_803e8430 * (float)((double)CONCAT44(0x43300000,param_1 & 0xff) - DOUBLE_803e8458)
        ;
        (&DAT_803bdfd0)[uVar2 * 0xc] = FLOAT_803e8440;
        (&DAT_803bdfd4)[uVar2 * 0xc] =
             FLOAT_803e846c / (float)((double)CONCAT44(0x43300000,local_4c[0]) - dVar7);
      }
      DAT_803deee0 = DAT_803deee0 | 1 << uVar4;
      return;
    }
    cVar3 = '\x01';
  }
  uStack_3c = param_1 & 0xff;
  pfVar5 = (float *)&DAT_803bdfc4;
  local_40 = 0x43300000;
  dVar8 = (double)FLOAT_803e8440;
  uVar4 = 0;
  dVar9 = (double)FLOAT_803e846c;
  dVar6 = (double)(FLOAT_803e8430 *
                  (float)((double)CONCAT44(0x43300000,uStack_3c) - DOUBLE_803e8458));
  dVar7 = DOUBLE_803e8458;
  do {
    if (*(char *)((int)pfVar5 + 0x2d) == cVar3) {
      *(undefined *)(pfVar5 + 0xb) = param_4;
      pfVar5[10] = -NAN;
      if (local_4c[0] == 0) {
        pfVar5[1] = (float)dVar6;
        *pfVar5 = (float)dVar6;
        if (pfVar5[10] != -NAN) {
          FUN_80271b90((int)pfVar5);
        }
      }
      else {
        uStack_3c = local_4c[0];
        local_40 = 0x43300000;
        pfVar5[2] = *pfVar5;
        pfVar5[1] = (float)dVar6;
        pfVar5[3] = (float)dVar8;
        pfVar5[4] = (float)(dVar9 / (double)(float)((double)CONCAT44(0x43300000,local_4c[0]) - dVar7
                                                   ));
      }
      DAT_803deee0 = DAT_803deee0 | 1 << uVar4;
    }
    uVar4 = uVar4 + 1;
    pfVar5 = pfVar5 + 0xc;
  } while (uVar4 < 0x20);
  return;
}


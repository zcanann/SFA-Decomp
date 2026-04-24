// Function: FUN_80271b4c
// Entry: 80271b4c
// Size: 1040 bytes

void FUN_80271b4c(uint param_1,uint param_2,uint param_3,undefined param_4,undefined4 param_5)

{
  float fVar1;
  char cVar2;
  uint uVar3;
  float *pfVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  uint local_4c;
  undefined4 local_48;
  uint uStack68;
  undefined4 local_40;
  uint uStack60;
  
  local_4c = param_2 & 0xffff;
  if (local_4c != 0) {
    FUN_80282f80(&local_4c);
  }
  uVar3 = param_3 & 0xff;
  if (uVar3 == 0xfd) {
    cVar2 = '\0';
  }
  else if (uVar3 < 0xfd) {
    if (uVar3 == 0xfb) {
      cVar2 = '\x03';
    }
    else {
      if (0xfa < uVar3) {
        uStack60 = param_1 & 0xff;
        pfVar4 = (float *)&DAT_803bd364;
        local_40 = 0x43300000;
        dVar8 = (double)FLOAT_803e77a8;
        uVar3 = 0;
        dVar7 = (double)FLOAT_803e77d4;
        dVar5 = (double)(FLOAT_803e7798 *
                        (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e77c0));
        dVar6 = DOUBLE_803e77c0;
        do {
          if ((*(char *)((int)pfVar4 + 0x2d) == '\x02') || (*(char *)((int)pfVar4 + 0x2d) == '\x03')
             ) {
            *(undefined *)(pfVar4 + 0xb) = param_4;
            pfVar4[10] = -NAN;
            if (local_4c == 0) {
              pfVar4[1] = (float)dVar5;
              *pfVar4 = (float)dVar5;
              if (pfVar4[10] != -NAN) {
                FUN_8027142c(pfVar4);
              }
            }
            else {
              uStack60 = local_4c;
              local_40 = 0x43300000;
              pfVar4[2] = *pfVar4;
              pfVar4[1] = (float)dVar5;
              pfVar4[3] = (float)dVar8;
              pfVar4[4] = (float)(dVar7 / (double)(float)((double)CONCAT44(0x43300000,local_4c) -
                                                         dVar6));
            }
            DAT_803de260 = DAT_803de260 | 1 << uVar3;
          }
          uVar3 = uVar3 + 1;
          pfVar4 = pfVar4 + 0xc;
        } while (uVar3 < 0x20);
        return;
      }
      if (uVar3 < 0xfa) goto LAB_80271e64;
      cVar2 = '\x02';
    }
  }
  else {
    if (uVar3 == 0xff) {
      uStack60 = param_1 & 0xff;
      pfVar4 = (float *)&DAT_803bd364;
      local_40 = 0x43300000;
      dVar8 = (double)FLOAT_803e77a8;
      uVar3 = 0;
      dVar7 = (double)FLOAT_803e77d4;
      dVar5 = (double)(FLOAT_803e7798 *
                      (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e77c0));
      dVar6 = DOUBLE_803e77c0;
      do {
        if ((*(char *)((int)pfVar4 + 0x2d) == '\0') || (*(char *)((int)pfVar4 + 0x2d) == '\x01')) {
          *(undefined *)(pfVar4 + 0xb) = param_4;
          pfVar4[10] = -NAN;
          if (local_4c == 0) {
            pfVar4[1] = (float)dVar5;
            *pfVar4 = (float)dVar5;
            if (pfVar4[10] != -NAN) {
              FUN_8027142c(pfVar4);
            }
          }
          else {
            uStack60 = local_4c;
            local_40 = 0x43300000;
            pfVar4[2] = *pfVar4;
            pfVar4[1] = (float)dVar5;
            pfVar4[3] = (float)dVar8;
            pfVar4[4] = (float)(dVar7 / (double)(float)((double)CONCAT44(0x43300000,local_4c) -
                                                       dVar6));
          }
          DAT_803de260 = DAT_803de260 | 1 << uVar3;
        }
        uVar3 = uVar3 + 1;
        pfVar4 = pfVar4 + 0xc;
      } while (uVar3 < 0x20);
      return;
    }
    if (0xfe < uVar3) {
LAB_80271e64:
      param_3 = param_3 & 0xff;
      (&DAT_803bd390)[param_3 * 0x30] = param_4;
      (&DAT_803bd38c)[param_3 * 0xc] = param_5;
      if (local_4c == 0) {
        uStack68 = param_1 & 0xff;
        local_48 = 0x43300000;
        fVar1 = FLOAT_803e7798 * (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e77c0);
        (&DAT_803bd368)[param_3 * 0xc] = fVar1;
        (&DAT_803bd364)[param_3 * 0xc] = fVar1;
        if ((&DAT_803bd38c)[param_3 * 0xc] != -1) {
          FUN_8027142c(&DAT_803bd364 + param_3 * 0xc);
        }
      }
      else {
        (&DAT_803bd36c)[param_3 * 0xc] = (&DAT_803bd364)[param_3 * 0xc];
        dVar6 = DOUBLE_803e77c0;
        (&DAT_803bd368)[param_3 * 0xc] =
             FLOAT_803e7798 * (float)((double)CONCAT44(0x43300000,param_1 & 0xff) - DOUBLE_803e77c0)
        ;
        (&DAT_803bd370)[param_3 * 0xc] = FLOAT_803e77a8;
        (&DAT_803bd374)[param_3 * 0xc] =
             FLOAT_803e77d4 / (float)((double)CONCAT44(0x43300000,local_4c) - dVar6);
      }
      DAT_803de260 = DAT_803de260 | 1 << uVar3;
      return;
    }
    cVar2 = '\x01';
  }
  uStack60 = param_1 & 0xff;
  pfVar4 = (float *)&DAT_803bd364;
  local_40 = 0x43300000;
  dVar7 = (double)FLOAT_803e77a8;
  uVar3 = 0;
  dVar8 = (double)FLOAT_803e77d4;
  dVar5 = (double)(FLOAT_803e7798 * (float)((double)CONCAT44(0x43300000,uStack60) - DOUBLE_803e77c0)
                  );
  dVar6 = DOUBLE_803e77c0;
  do {
    if (*(char *)((int)pfVar4 + 0x2d) == cVar2) {
      *(undefined *)(pfVar4 + 0xb) = param_4;
      pfVar4[10] = -NAN;
      if (local_4c == 0) {
        pfVar4[1] = (float)dVar5;
        *pfVar4 = (float)dVar5;
        if (pfVar4[10] != -NAN) {
          FUN_8027142c(pfVar4);
        }
      }
      else {
        uStack60 = local_4c;
        local_40 = 0x43300000;
        pfVar4[2] = *pfVar4;
        pfVar4[1] = (float)dVar5;
        pfVar4[3] = (float)dVar7;
        pfVar4[4] = (float)(dVar8 / (double)(float)((double)CONCAT44(0x43300000,local_4c) - dVar6));
      }
      DAT_803de260 = DAT_803de260 | 1 << uVar3;
    }
    uVar3 = uVar3 + 1;
    pfVar4 = pfVar4 + 0xc;
  } while (uVar3 < 0x20);
  return;
}


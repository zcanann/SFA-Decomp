// Function: FUN_8013f488
// Entry: 8013f488
// Size: 2276 bytes

/* WARNING: Removing unreachable block (ram,0x8013fd48) */
/* WARNING: Removing unreachable block (ram,0x8013f498) */

void FUN_8013f488(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int *param_10,undefined4 param_11,undefined4 param_12,byte param_13,
                 uint param_14,undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  bool bVar4;
  uint uVar2;
  int iVar3;
  undefined **ppuVar5;
  double dVar6;
  
  ppuVar5 = &switchD_8013f4d0::switchdataD_8031e560;
  switch(*(undefined *)((int)param_10 + 10)) {
  case 0:
    param_10[0x1c0] = param_10[9];
    param_10[0x1c1] = (int)FLOAT_803e317c;
    *(undefined *)((int)param_10 + 10) = 1;
    uVar2 = FUN_80022264(0x96,300);
    param_10[0x1e9] =
         (int)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e30f0);
  case 1:
    iVar3 = FUN_80179b18(param_10[0x1c0]);
    if (iVar3 == 0) {
      iVar3 = FUN_8013b6f0((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,param_10,(int)ppuVar5,param_12,param_13,param_14,param_15
                           ,param_16);
      if (iVar3 == 0) {
        if ((float)param_10[0x1c1] <= FLOAT_803e306c) {
          FUN_8013a778((double)FLOAT_803e30cc,param_9,0x10,0x4000000);
          param_10[0x1c2] = (int)((float)param_10[0x1c2] - FLOAT_803dc074);
          if ((float)param_10[0x1c2] <= FLOAT_803e306c) {
            param_10[0x1c1] = (int)FLOAT_803e317c;
          }
        }
        else {
          if (FLOAT_803e306c == (float)param_10[0xab]) {
            bVar4 = false;
          }
          else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
            bVar4 = true;
          }
          else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
            bVar4 = false;
          }
          else {
            bVar4 = true;
          }
          if (bVar4) {
            FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
            param_10[0x1e7] = (int)FLOAT_803e30d0;
            param_10[0x20e] = (int)FLOAT_803e306c;
            FUN_80148ff0();
          }
          else {
            FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
            FUN_80148ff0();
          }
          param_10[0x1c1] = (int)((float)param_10[0x1c1] - FLOAT_803dc074);
          if ((float)param_10[0x1c1] <= FLOAT_803e306c) {
            if (FLOAT_803e306c == (float)param_10[0xab]) {
              bVar4 = false;
            }
            else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
              bVar4 = true;
            }
            else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
              bVar4 = false;
            }
            else {
              bVar4 = true;
            }
            if (bVar4) {
              param_10[0x1c1] = (int)FLOAT_803e317c;
            }
            else {
              param_10[0x1c2] = (int)FLOAT_803e3188;
            }
          }
        }
      }
      else if (iVar3 == 1) {
        param_10[0x1e9] = (int)((float)param_10[0x1e9] - FLOAT_803dc074);
        if ((float)param_10[0x1e9] <= FLOAT_803e306c) {
          uVar2 = FUN_80022264(0x96,300);
          param_10[0x1e9] =
               (int)(float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e30f0);
          iVar3 = *(int *)(param_9 + 0xb8);
          if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
             (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
              (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)))) {
            FUN_800394f0(param_9,iVar3 + 0x3a8,0x361,0x500,0xffffffff,0);
          }
        }
      }
      else {
        if (FLOAT_803e306c == (float)param_10[0xab]) {
          bVar4 = false;
        }
        else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
          bVar4 = true;
        }
        else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
          bVar4 = false;
        }
        else {
          bVar4 = true;
        }
        if (bVar4) {
          FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
          param_10[0x1e7] = (int)FLOAT_803e30d0;
          param_10[0x20e] = (int)FLOAT_803e306c;
          FUN_80148ff0();
        }
        else {
          FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
          FUN_80148ff0();
        }
      }
    }
    else {
      iVar3 = FUN_8013b6f0((double)FLOAT_803e3180,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,param_10,(int)ppuVar5,param_12,param_13,param_14,param_15
                           ,param_16);
      if (iVar3 == 0) {
        if (FLOAT_803e306c == (float)param_10[0xab]) {
          bVar4 = false;
        }
        else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
          bVar4 = true;
        }
        else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
          bVar4 = false;
        }
        else {
          bVar4 = true;
        }
        if (bVar4) {
          FUN_8013a778((double)FLOAT_803e3184,param_9,0x1c,0x4000000);
        }
        else {
          FUN_8013a778((double)FLOAT_803e3184,param_9,0x11,0x4000000);
        }
        param_10[0x15] = param_10[0x15] | 0x10;
        *(undefined *)((int)param_10 + 10) = 3;
        FUN_80179b40(param_10[0x1c0]);
      }
      else if (iVar3 == 2) {
        iVar3 = *(int *)(param_9 + 0xb8);
        if ((((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
            ((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)))) &&
           (bVar4 = FUN_8000b598(param_9,0x10), !bVar4)) {
          FUN_800394f0(param_9,iVar3 + 0x3a8,0x35d,0x500,0xffffffff,0);
        }
        *(undefined *)(param_10 + 2) = 1;
        *(undefined *)((int)param_10 + 10) = 0;
        fVar1 = FLOAT_803e306c;
        param_10[0x1c7] = (int)FLOAT_803e306c;
        param_10[0x1c8] = (int)fVar1;
        param_10[0x15] = param_10[0x15] & 0xffffffef;
        param_10[0x15] = param_10[0x15] & 0xfffeffff;
        param_10[0x15] = param_10[0x15] & 0xfffdffff;
        param_10[0x15] = param_10[0x15] & 0xfffbffff;
        *(undefined *)((int)param_10 + 0xd) = 0xff;
      }
    }
    break;
  case 2:
    if ((param_10[0x15] & 0x8000000U) != 0) {
      param_10[0x20a] = (int)FLOAT_803e3098;
      iVar3 = *param_10;
      if (*(byte *)(iVar3 + 2) < 0xef) {
        *(byte *)(iVar3 + 2) = *(byte *)(iVar3 + 2) + 1;
      }
      else {
        *(undefined *)(iVar3 + 2) = 0;
      }
      param_10[0x15] = param_10[0x15] & 0xffffffef;
      *(undefined *)((int)param_10 + 10) = 7;
      if (param_10[10] != param_10[9] + 0x18) {
        param_10[10] = param_10[9] + 0x18;
        param_10[0x15] = param_10[0x15] & 0xfffffbff;
        *(undefined2 *)((int)param_10 + 0xd2) = 0;
      }
    }
    break;
  case 3:
    if (FLOAT_803e3138 <= *(float *)(param_9 + 0x98)) {
      *(undefined *)((int)param_10 + 10) = 4;
    }
    break;
  case 4:
    if (*(float *)(param_9 + 0x98) < FLOAT_803e3160) break;
    if (param_10[10] != param_10[1] + 0x18) {
      param_10[10] = param_10[1] + 0x18;
      param_10[0x15] = param_10[0x15] & 0xfffffbff;
      *(undefined2 *)((int)param_10 + 0xd2) = 0;
    }
    *(undefined *)((int)param_10 + 10) = 5;
  case 5:
    iVar3 = FUN_8013b6f0((double)FLOAT_803e3158,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,-0x7fce1aa0,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar3 == 0) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_8013a778((double)FLOAT_803e3184,param_9,0x1d,0x4000000);
      }
      else {
        FUN_8013a778((double)FLOAT_803e3184,param_9,0x13,0x4000000);
      }
      *(undefined *)((int)param_10 + 10) = 6;
    }
    break;
  case 6:
    if (FLOAT_803e318c <= *(float *)(param_9 + 0x98)) {
      *(float *)(param_10[0x1c0] + 0x10) = *(float *)(param_10[0x1c0] + 0x10) + FLOAT_803e3118;
      dVar6 = (double)FUN_80294964();
      param_3 = -dVar6;
      dVar6 = (double)FUN_802945e0();
      param_2 = (double)FLOAT_803e3078;
      FUN_80179b84(-dVar6,param_2,param_3,param_10[0x1c0]);
      *(undefined *)((int)param_10 + 10) = 2;
    }
    break;
  case 7:
    iVar3 = FUN_8013b6f0((double)FLOAT_803e3098,param_2,param_3,param_4,param_5,param_6,param_7,
                         param_8,param_9,param_10,-0x7fce1aa0,param_12,param_13,param_14,param_15,
                         param_16);
    if (iVar3 != 1) {
      if (FLOAT_803e306c == (float)param_10[0xab]) {
        bVar4 = false;
      }
      else if (FLOAT_803e30a0 == (float)param_10[0xac]) {
        bVar4 = true;
      }
      else if ((float)param_10[0xad] - (float)param_10[0xac] <= FLOAT_803e30a4) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
        FUN_8013a778((double)FLOAT_803e30cc,param_9,8,0);
        param_10[0x1e7] = (int)FLOAT_803e30d0;
        param_10[0x20e] = (int)FLOAT_803e306c;
        FUN_80148ff0();
        return;
      }
      FUN_8013a778((double)FLOAT_803e30d4,param_9,0,0);
      FUN_80148ff0();
      return;
    }
    uVar2 = FUN_80179850(param_10[9]);
    if (uVar2 != 0) {
      param_10[0x1c1] = (int)FLOAT_803e317c;
      *(undefined *)((int)param_10 + 10) = 1;
    }
  }
  if ((param_10[0x15] & 0x10000U) != 0) {
    dVar6 = (double)FLOAT_803e3190;
    iVar3 = FUN_8005a288(dVar6,(float *)(param_9 + 0xc));
    if (iVar3 == 0) {
      FUN_8002cc9c(dVar6,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_10[9]);
      return;
    }
  }
  FUN_80179af4(param_10[0x1c0]);
  return;
}


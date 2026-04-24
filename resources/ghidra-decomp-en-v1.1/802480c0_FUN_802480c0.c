// Function: FUN_802480c0
// Entry: 802480c0
// Size: 40 bytes

/* WARNING: Removing unreachable block (ram,0x802480d0) */
/* WARNING: Removing unreachable block (ram,0x802480cc) */
/* WARNING: Removing unreachable block (ram,0x802480c4) */
/* WARNING: Removing unreachable block (ram,0x802480c0) */

double FUN_802480c0(float *param_1,float *param_2)

{
  return ((double)*param_1 - (double)*param_2) * ((double)*param_1 - (double)*param_2) +
         ((double)param_1[1] - (double)param_2[1]) * ((double)param_1[1] - (double)param_2[1]) +
         ((double)param_1[2] - (double)param_2[2]) * ((double)param_1[2] - (double)param_2[2]);
}


/***********************************************************************************************//**
 *  \brief      VITOW - (Reliable) Video Transfer over WiFi - Debug functionalities.
 *  \details    An experimental protocol.
 *  \author     Maties Pons, Carles Araguz <carles.araguz@upc.edu>
 *  \version    1.0
 *  \date       14-nov-2016
 *  \copyright  GNU Public License (v3). This files are part of an on-going non-commercial research
 *              project at NanoSat Lab (http://nanosatlab.upc.edu) of the Technical University of
 *              Catalonia - UPC BarcelonaTech. Third-party libraries used in this framework might be
 *              subject to different copyright conditions.
 *  \note       Fork by Carles Araguz - carles.araguz@upc.edu.
 **************************************************************************************************/

/*** INCLUDE SECTION ******************************************************************************/
#include "vitow.h"


/*** GLOBAL VARIABLES *****************************************************************************/


/***********************************************************************************************//**
 * Chack that all the debug data fields have been filled.
 **************************************************************************************************/
bool check_dbg_data(HKData * hkd)
{
    /* This condition fails to acknowledge that some values could actually be "0". Despite that,
     * this is very unlikely in a real-world case in which it is uncommon to read an absolute "0"
     * from a sensor. If there would be such case, this condition would only prevent to store the
     * data, which, for this application, is not critical.
     */
    return (
        hkd->gps.time_local   != 0      &&
        hkd->gps.time_gps     != 0      &&
        hkd->gps.lat          != 0.f    &&
        hkd->gps.lng          != 0.f    &&
        hkd->gps.gspeed       != 0.f    &&
        hkd->gps.sea_alt      != 0.f    &&
        hkd->gps.geo_alt      != 0.f    &&
        hkd->mot.acc_x        != 0.f    &&
        hkd->mot.acc_x        != 0.f    &&
        hkd->mot.acc_y        != 0.f    &&
        hkd->mot.acc_z        != 0.f    &&
        hkd->mot.gyro_x       != 0.f    &&
        hkd->mot.gyro_y       != 0.f    &&
        hkd->mot.gyro_z       != 0.f    &&
        hkd->mot.mag_x        != 0.f    &&
        hkd->mot.mag_y        != 0.f    &&
        hkd->mot.mag_z        != 0.f    &&
        hkd->amb.cpu_temp     != 0.f    &&
        hkd->amb.gpu_temp     != 0.f    &&
        hkd->amb.in_temp      != 0.f    &&
        hkd->amb.in_pressure  != 0.f    &&
        hkd->amb.in_calc_alt  != 0.f    &&
        hkd->amb.out_temp     != 0.f    &&
        hkd->amb.out_pressure != 0.f    &&
        hkd->amb.out_calc_alt != 0.f
    );
}
/***********************************************************************************************//**
 * Select and copy debug data.
 **************************************************************************************************/
void dump_dbg_data(int dbg_id, HKData * hkd, unsigned int * dbg_param, unsigned int * dbg_value)
{
    switch(dbg_id) {
        case DBG_PARAM_GPS_TIME_LOCAL:
            *dbg_param = htonl(DBG_PARAM_GPS_TIME_LOCAL);
            memcpy(dbg_value, &hkd->gps.time_local, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_TIME_GPS:
            *dbg_param = htonl(DBG_PARAM_GPS_TIME_GPS);
            memcpy(dbg_value, &hkd->gps.time_gps, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_LAT:
            *dbg_param = htonl(DBG_PARAM_GPS_LAT);
            memcpy(dbg_value, &hkd->gps.lat, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_LNG:
            *dbg_param = htonl(DBG_PARAM_GPS_LNG);
            memcpy(dbg_value, &hkd->gps.lng, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_GSPEED:
            *dbg_param = htonl(DBG_PARAM_GPS_GSPEED);
            memcpy(dbg_value, &hkd->gps.gspeed, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_SEA_ALT:
            *dbg_param = htonl(DBG_PARAM_GPS_SEA_ALT);
            memcpy(dbg_value, &hkd->gps.sea_alt, sizeof(*dbg_value));
            *dbg_value = htonl(*dbg_value);
            break;
        case DBG_PARAM_GPS_GEO_ALT:
            *dbg_param = htonl(DBG_PARAM_GPS_GEO_ALT);
            memcpy(dbg_value, &hkd->gps.geo_alt, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_X:
            *dbg_param = htonl(DBG_PARAM_MOT_ACC_X);
            memcpy(dbg_value, &hkd->mot.acc_x, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_Y:
            *dbg_param = htonl(DBG_PARAM_MOT_ACC_Y);
            memcpy(dbg_value, &hkd->mot.acc_y, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_Z:
            *dbg_param = htonl(DBG_PARAM_MOT_ACC_Z);
            memcpy(dbg_value, &hkd->mot.acc_z, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_X:
            *dbg_param = htonl(DBG_PARAM_MOT_GYRO_X);
            memcpy(dbg_value, &hkd->mot.gyro_x, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_Y:
            *dbg_param = htonl(DBG_PARAM_MOT_GYRO_Y);
            memcpy(dbg_value, &hkd->mot.gyro_y, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_Z:
            *dbg_param = htonl(DBG_PARAM_MOT_GYRO_Z);
            memcpy(dbg_value, &hkd->mot.gyro_z, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_X:
            *dbg_param = htonl(DBG_PARAM_MOT_MAG_X);
            memcpy(dbg_value, &hkd->mot.mag_x, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_Y:
            *dbg_param = htonl(DBG_PARAM_MOT_MAG_Y);
            memcpy(dbg_value, &hkd->mot.mag_y, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_Z:
            *dbg_param = htonl(DBG_PARAM_MOT_MAG_Z);
            memcpy(dbg_value, &hkd->mot.mag_z, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_CPU_TEMP:
            *dbg_param = htonl(DBG_PARAM_AMB_CPU_TEMP);
            memcpy(dbg_value, &hkd->amb.cpu_temp, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_GPU_TEMP:
            *dbg_param = htonl(DBG_PARAM_AMB_GPU_TEMP);
            memcpy(dbg_value, &hkd->amb.gpu_temp, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_TEMP:
            *dbg_param = htonl(DBG_PARAM_AMB_IN_TEMP);
            memcpy(dbg_value, &hkd->amb.in_temp, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_PRESSURE:
            *dbg_param = htonl(DBG_PARAM_AMB_IN_PRESSURE);
            memcpy(dbg_value, &hkd->amb.in_pressure, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_CALC_ALT:
            *dbg_param = htonl(DBG_PARAM_AMB_IN_CALC_ALT);
            memcpy(dbg_value, &hkd->amb.in_calc_alt, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_TEMP:
            *dbg_param = htonl(DBG_PARAM_AMB_OUT_TEMP);
            memcpy(dbg_value, &hkd->amb.out_temp, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_PRESSURE:
            *dbg_param = htonl(DBG_PARAM_AMB_OUT_PRESSURE);
            memcpy(dbg_value, &hkd->amb.out_pressure, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_CALC_ALT:
            *dbg_param = htonl(DBG_PARAM_AMB_OUT_CALC_ALT);
            memcpy(dbg_value, &hkd->amb.out_calc_alt, sizeof(*dbg_value));
            break;
        default:
            *dbg_param = 0;
            *dbg_value = 0;
            break;
    }
    *dbg_value = htonl(*dbg_value);
}

void save_dbg_data(unsigned int dbg_param, unsigned int * dbg_value, HKData * hkd)
{
    /* dbg_param indicates the ID of the parameter sent */
   switch (dbg_param) {
        case DBG_PARAM_GPS_TIME_LOCAL:
            memcpy(&hkd->gps.time_local, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_TIME_GPS:
            memcpy(&hkd->gps.time_gps, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_LAT:
            memcpy(&hkd->gps.lat, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_LNG:
            memcpy(&hkd->gps.lng, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_GSPEED:
            memcpy(&hkd->gps.gspeed, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_SEA_ALT:
            memcpy(&hkd->gps.sea_alt, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_GPS_GEO_ALT:
            memcpy(&hkd->gps.geo_alt, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_X:
            memcpy(&hkd->mot.acc_x, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_Y:
            memcpy(&hkd->mot.acc_y, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_ACC_Z:
            memcpy(&hkd->mot.acc_z, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_X:
            memcpy(&hkd->mot.gyro_x, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_Y:
            memcpy(&hkd->mot.gyro_y, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_GYRO_Z:
            memcpy(&hkd->mot.gyro_z, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_X:
            memcpy(&hkd->mot.mag_x, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_Y:
            memcpy(&hkd->mot.mag_y, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_MOT_MAG_Z:
            memcpy(&hkd->mot.mag_z, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_CPU_TEMP:
            memcpy(&hkd->amb.cpu_temp, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_GPU_TEMP:
            memcpy(&hkd->amb.gpu_temp, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_TEMP:
            memcpy(&hkd->amb.in_temp, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_PRESSURE:
            memcpy(&hkd->amb.in_pressure, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_IN_CALC_ALT:
            memcpy(&hkd->amb.in_calc_alt, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_TEMP:
            memcpy(&hkd->amb.out_temp, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_PRESSURE:
            memcpy(&hkd->amb.out_pressure, dbg_value, sizeof(*dbg_value));
            break;
        case DBG_PARAM_AMB_OUT_CALC_ALT:
            memcpy(&hkd->amb.out_calc_alt, dbg_value, sizeof(*dbg_value));
            break;
        default:
            break;
    }
}
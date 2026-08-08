/**************************************************************************/
/*                                                                        */
/*       Copyright (c) Microsoft Corporation. All rights reserved.        */
/*                                                                        */
/*       This software is licensed under the Microsoft Software License   */
/*       Terms for Microsoft Azure RTOS. Full text of the license can be  */
/*       found in the LICENSE file at https://aka.ms/AzureRTOS_EULA       */
/*       and in the root directory of this software.                      */
/*                                                                        */
/**************************************************************************/


/**************************************************************************/
/**************************************************************************/
/**                                                                       */
/** NetX Component                                                        */
/**                                                                       */
/**   Transmission Control Protocol (TCP)                                 */
/**                                                                       */
/**************************************************************************/
/**************************************************************************/

#define NX_SOURCE_CODE


/* Include necessary system files.  */

#include "nx_api.h"
#include "nx_tcp.h"


#ifdef NX_ENABLE_TCP_TIMESTAMP
/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_timestamp_option_get                        PORTABLE C      */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This function searches a TCP option area for the timestamps option  */
/*    of RFC 1323 section 3.2 and returns the two values it carries.      */
/*                                                                        */
/*    Written against _nx_tcp_window_scaling_option_get(), which walks    */
/*    the same area the same way; the difference is that this option is   */
/*    ten bytes rather than three and is legal on every segment, not      */
/*    only on a SYN.                                                      */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    option_ptr                            Pointer to option area        */
/*    option_area_size                      Size of option area           */
/*    timestamp_value                       Returned TSval                */
/*    timestamp_echo                        Returned TSecr                */
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_TRUE                               The option was present        */
/*    NX_FALSE                              It was not, or was malformed  */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_timestamp_option_get(UCHAR *option_ptr, ULONG option_area_size,
                                   ULONG *timestamp_value, ULONG *timestamp_echo)
{

    *timestamp_value = 0;
    *timestamp_echo  = 0;

    /* The option is ten bytes, so anything shorter than that cannot hold one. */
    while (option_area_size >= (ULONG)NX_TCP_TIMESTAMP_LENGTH)
    {

        if (*option_ptr == NX_TCP_TIMESTAMP_KIND)
        {

            /* Found it.  A length field that does not say ten means the sender
               and this reader disagree about the option, and the safe reading
               of a disagreement is that there is no timestamp here.  */
            if (*(option_ptr + 1) != (UCHAR)NX_TCP_TIMESTAMP_LENGTH)
            {
                return(NX_FALSE);
            }

            /* Both values are network order, and neither is guaranteed to be
               word aligned inside the option area, so they are assembled a
               byte at a time.  */
            *timestamp_value = (((ULONG)(*(option_ptr + 2))) << 24) |
                               (((ULONG)(*(option_ptr + 3))) << 16) |
                               (((ULONG)(*(option_ptr + 4))) << 8) |
                                ((ULONG)(*(option_ptr + 5)));

            *timestamp_echo  = (((ULONG)(*(option_ptr + 6))) << 24) |
                               (((ULONG)(*(option_ptr + 7))) << 16) |
                               (((ULONG)(*(option_ptr + 8))) << 8) |
                                ((ULONG)(*(option_ptr + 9)));

            return(NX_TRUE);
        }

        /* End of the list: nothing further is an option.  */
        if (*option_ptr == NX_TCP_EOL_KIND)
        {
            break;
        }

        /* A NOP is one byte and carries no length.  */
        if (*option_ptr == NX_TCP_NOP_KIND)
        {
            option_ptr++;
            option_area_size--;
            continue;
        }

        /* Anything else is kind, length, payload.  A length below two would
           not advance and would spin here, so it ends the walk.  */
        if (*(option_ptr + 1) < 2)
        {
            break;
        }

        if ((ULONG)(*(option_ptr + 1)) > option_area_size)
        {
            break;
        }

        option_area_size -= (ULONG)(*(option_ptr + 1));
        option_ptr       += (ULONG)(*(option_ptr + 1));
    }

    return(NX_FALSE);
}
#endif /* NX_ENABLE_TCP_TIMESTAMP */

/***************************************************************************
 * Copyright (c) 2024 Microsoft Corporation
 * Copyright (c) 2025-present Eclipse ThreadX Contributors
 *
 * This program and the accompanying materials are made available under the
 * terms of the MIT License which is available at
 * https://opensource.org/licenses/MIT.
 *
 * SPDX-License-Identifier: MIT
 **************************************************************************/


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

#ifdef NX_ENABLE_TCP_SACK

/**************************************************************************/
/*                                                                        */
/*  FUNCTION                                               RELEASE        */
/*                                                                        */
/*    _nx_tcp_sack_permitted_option_get                   PORTABLE C      */
/*                                                           6.4.3        */
/*  AUTHOR                                                                */
/*                                                                        */
/*    Eclipse ThreadX Contributors                                        */
/*                                                                        */
/*  DESCRIPTION                                                           */
/*                                                                        */
/*    This internal function searches for the SACK-Permitted option in a  */
/*    SYN segment, RFC 2018 section 2.  If the option area is malformed   */
/*    NX_FALSE is returned, otherwise NX_TRUE is returned and             */
/*    sack_permitted says whether the option was present.                 */
/*                                                                        */
/*  INPUT                                                                 */
/*                                                                        */
/*    option_ptr                            Pointer to option area        */
/*    option_area_size                      Size of option area           */
/*    sack_permitted                        NX_TRUE if the option is there*/
/*                                                                        */
/*  OUTPUT                                                                */
/*                                                                        */
/*    NX_FALSE                              TCP option is invalid         */
/*    NX_TRUE                               TCP option is valid           */
/*                                                                        */
/*  CALLS                                                                 */
/*                                                                        */
/*    None                                                                */
/*                                                                        */
/*  CALLED BY                                                             */
/*                                                                        */
/*    _nx_tcp_packet_process                TCP packet processing         */
/*    _nx_tcp_server_socket_relisten        Socket relisten processing    */
/*                                                                        */
/**************************************************************************/
UINT  _nx_tcp_sack_permitted_option_get(UCHAR *option_ptr, ULONG option_area_size, ULONG *sack_permitted)
{

ULONG option_length;


    /* Assume the peer does not support SACK until the option is seen.  */
    *sack_permitted = NX_FALSE;

    /* Loop through the option area looking for the SACK-Permitted option.  */
    while (option_area_size >= 2)
    {

        /* Is the current character the SACK-Permitted type?  */
        if (*option_ptr == NX_TCP_SACK_PERMITTED_KIND)
        {

            /* Check the option length, if option length is not equal to 2, return NX_FALSE.  */
            if (*(option_ptr + 1) != 2)
            {
                return(NX_FALSE);
            }

            *sack_permitted = NX_TRUE;

            break;
        }

        /* Otherwise, process relative to the option type.  */

        /* Check for end of list.  */
        if (*option_ptr == NX_TCP_EOL_KIND)
        {

            /* Yes, end of list, get out!  */
            break;
        }

        /* Check for NOP.  */
        if (*option_ptr == NX_TCP_NOP_KIND)
        {
            /* One character option!  Skip this option and move to the next entry. */
            option_ptr++;

            option_area_size--;
        }
        else
        {

            /* Derive the option length.  All options *fields* area 32-bits,
               but the options themselves may be padded by NOP's.   Determine
               the option size based on alignment of the option ptr */
            option_length = *(option_ptr + 1);

            if (option_length == 0)
            {
                /* Illegal option length. */
                return(NX_FALSE);
            }

            /* Move the option pointer forward.  */
            option_ptr =  option_ptr + option_length;

            /* Determine if this is greater than the option area size.  */
            if (option_length > option_area_size)
            {
                return(NX_FALSE);
            }
            else
            {
                option_area_size =  option_area_size - option_length;
            }
        }
    }

    /* Return.  */
    return(NX_TRUE);
}
#endif /* NX_ENABLE_TCP_SACK */

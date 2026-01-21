
// FullConeClient Authorizer
client_auth_kind CFullConeAuthorizer::authorize(authdata_t* authdata)
{
    enum
    {
        FULLCONE_MAGIC = 0x46434343,  // "FCCC" in little-endian
        FULLCONE_VERSION_V1 = 0x01,
        FULLCONE_VERSION_V2 = 0x02,
        FULLCONE_VERSION_V3 = 0x03,
        TICKET_SIZE_V1V2 = 32,
        TICKET_SIZE_V3 = 72,
        CUSTOM_ID_MAX_LEN = 63
    };

    struct FullConeTicketV2_t
    {
        uint32_t Magic;
        uint32_t Version;
        uint32_t Prefix;
        CSteamID SteamID;
        uint32_t Reserved2;
        uint32_t Reserved3;
        uint32_t Checksum;
    };

    struct FullConeTicketV3_t
    {
        uint32_t Magic;
        uint32_t Version;
        char CustomID[64];
    };

    if (authdata->ticketLen < 8) {
        return CA_UNKNOWN;
    }

    uint32_t* header = (uint32_t*)authdata->authTicket;
    if (header[0] != FULLCONE_MAGIC) {
        return CA_UNKNOWN;
    }

    uint32_t version = header[1];

    if (version == FULLCONE_VERSION_V3) {
        if (authdata->ticketLen != TICKET_SIZE_V3) {
            return CA_UNKNOWN;
        }
        FullConeTicketV3_t* ticket = (FullConeTicketV3_t*)authdata->authTicket;
        ticket->CustomID[CUSTOM_ID_MAX_LEN] = 0;

        authdata->idtype = AUTH_IDTYPE_STEAM;
        authdata->steamId = STEAM_ID_LAN;
        authdata->authKeyKind = AK_OTHER;
        authdata->authKeyLen = strlen(ticket->CustomID);
        strncpy((char*)authdata->authKey, ticket->CustomID, sizeof(authdata->authKey) - 1);
        authdata->authKey[sizeof(authdata->authKey) - 1] = 0;

        return CA_FULLCONE;
    }

    if (authdata->ticketLen != TICKET_SIZE_V1V2) {
        return CA_UNKNOWN;
    }

    if (version != FULLCONE_VERSION_V1 && version != FULLCONE_VERSION_V2) {
        return CA_UNKNOWN;
    }

    FullConeTicketV2_t* ticket = (FullConeTicketV2_t*)authdata->authTicket;

    uint32_t* data = (uint32_t*)authdata->authTicket;
    uint32_t checksum = data[0] ^ data[1] ^ data[2] ^ data[3] ^ data[4] ^ data[5] ^ data[6];
    if (checksum != ticket->Checksum) {
        return CA_UNKNOWN;
    }

    uint32_t accId = ticket->SteamID.GetAccountID();
    authdata->idtype = AUTH_IDTYPE_STEAM;

    if (accId == STEAM_ID_LAN || accId == 0) {
        authdata->steamId = STEAM_ID_PENDING;
        authdata->authKeyKind = AK_OTHER;
        authdata->authKeyLen = 0;
    }
    else {
        authdata->steamId = accId;
        authdata->authKeyKind = (version == FULLCONE_VERSION_V2) ? (auth_key_kind)ticket->Prefix : AK_STEAM;
        authdata->authKeyLen = sizeof(uint32_t);
        *(uint32_t *)authdata->authKey = accId;
    }

    return CA_FULLCONE;
}

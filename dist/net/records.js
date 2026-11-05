/**
 * Queries `name` and returns the data of every answer of `type` whose data is a string
 * (addresses for A/AAAA, host names for NS). Answers of other types, such as CNAMEs
 * along the way, are skipped.
 */
export async function stringRecords(dns, type, name) {
    const packet = await dns.query({ type, name });
    return (packet.answers ?? []).flatMap((a) => {
        const data = a.data;
        return a.type === type && typeof data === "string" ? [data] : [];
    });
}

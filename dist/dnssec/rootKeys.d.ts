export interface RootTrustAnchor {
    keyTag: number;
    algorithm: number;
    digestType: number;
    digestHex: string;
}
export declare const ROOT_TRUST_ANCHORS: readonly RootTrustAnchor[];

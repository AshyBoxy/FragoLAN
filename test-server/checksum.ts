export const calculateChecksum = (header: number[]): number => {
    let check: number = 0;
    for (let i = 0; i < 20; i += 2) {
        if (i === 10) continue; // skip the checksum itself
        const num = (header[i] << 8) | header[i + 1];
        console.log(num.toString(16));
        check += num;
    };

    let sum: number = check & 0xFFFF;

    let newSum = sum + (check >> 16);
    let notSum = (~newSum) & 0xFFFF;

    console.log({ check: check.toString(16), sum: sum.toString(16), newSum: newSum.toString(16), notSum: notSum.toString(16) });

    return notSum;
};

export const validateChecksum = (header: number[]): boolean => {
    let check: number = 0;
    for (let i = 0; i < 20; i += 2) {
        const num = (header[i] << 8) | header[i + 1];
        check += num;
    }

    let sum: number = check & 0xFFFF;
    let newSum = sum + (check >> 16);
    let notSum = (~newSum) & 0xff;

    console.log({ check: check.toString(16), sum: sum.toString(16), newSum: newSum.toString(16), notSum: notSum.toString(16) });

    return notSum === 0;
};

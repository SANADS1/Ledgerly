import * as bcrypt from 'bcrypt';

export class PasswordService {
    private static readonly SALT_ROUNDS = 12;

    static async hash(password: string): Promise<string> {
        return bcrypt.hash(password, this.SALT_ROUNDS);
    }

    static async verify(password: string, hash: string): Promise<boolean> {
        return bcrypt.compare(password, hash);
    }
}

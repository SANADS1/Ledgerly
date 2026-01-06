import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { Role } from '../../generated/prisma';

interface JwtPayload {
    sub: string;
    role: Role;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
    constructor(config: ConfigService) {
        super({
            jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
            secretOrKey: config.get<string>('JWT_ACCESS_SECRET') || '',
        });
    }

    validate(payload: JwtPayload) {
        return {
            userId: payload.sub,
            role: payload.role,
        };
    }
}

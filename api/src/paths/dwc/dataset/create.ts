import { RequestHandler } from 'express';
import { Operation } from 'express-openapi';
import { getDBConnection } from '../../../database/db';
import { HTTP400 } from '../../../errors/http-error';
import { defaultErrorResponses } from '../../../openapi/schemas/http-responses';
import { authorizeRequestHandler } from '../../../request-handlers/security/authorization';
import { generateS3FileKey, scanFileForVirus, uploadFileToS3 } from '../../../utils/file-utils';
import { getLogger } from '../../../utils/logger';

const defaultLog = getLogger('paths/dwc/dataset/create');

export const GET: Operation = [
  authorizeRequestHandler(() => {
    return {
      and: [
        {
          discriminator: 'SystemUser'
        }
      ]
    };
  }),
  submitDataset()
];

GET.apiDoc = {
  description: 'Submit a new Darwin Core (DwC) data package.',
  tags: ['misc'],
  security: [
    {
      Bearer: []
    }
  ],
  requestBody: {
    content: {
      'multipart/form-data': {
        schema: {
          type: 'object',
          required: ['data_set'],
          properties: {
            data_set: {
              type: 'string',
              format: 'binary'
            }
          }
        }
      }
    }
  },
  responses: {
    200: {
      description: 'Submission OK.',
      content: {
        'application/json': {
          schema: {
            type: 'object',
            required: ['data_package_id'],
            properties: {
              data_package_id: {
                type: 'string'
              }
            }
          }
        }
      }
    },
    ...defaultErrorResponses
  }
};

export function submitDataset(): RequestHandler {
  return async (req, res) => {
    if (!req.files || !req.files.length) {
      throw new HTTP400('Missing upload data');
    }

    const rawMediaFile: Express.Multer.File = req.files[0];

    const metadata = {
      filename: rawMediaFile.originalname
    };

    const connection = getDBConnection(req['keycloak_token']);

    if (!(await scanFileForVirus(rawMediaFile))) {
      throw new HTTP400('Malicious content detected, upload cancelled');
    }

    defaultLog.debug({
      label: 'uploadMedia',
      message: 'file',
      file: { ...rawMediaFile, buffer: 'Too big to print' }
    });

    try {
      await connection.open();

      const s3Key = generateS3FileKey({
        folder: '',
        fileName: 'dwc-archive'
      });

      await uploadFileToS3(rawMediaFile, s3Key, metadata);

      await connection.commit();

      res.status(200).json({ data_package_id: 1 });
    } catch (error) {
      defaultLog.error({ label: 'uploadMedia', message: 'error', error });
      await connection.rollback();
      throw error;
    } finally {
      connection.release();
    }
  };
}

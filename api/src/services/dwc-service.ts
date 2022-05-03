import { DBService } from './service';
import { HTTP400 } from '../errors/http-error';
import { Queries } from '../queries';
import { PostOccurrence } from '../models/occurrence/create';
import { DWCArchive } from '../utils/media/dwc/dwc-archive-file';

export class DarwinCoreService extends DBService {
  async getS3Key(submissionId: number) {
    const sqlStatement = await Queries.submission.view.getSubmissionForViewSQL(submissionId);

    if (!sqlStatement) {
      throw new HTTP400('Failed to build SQL get statement');
    }

    const response = await this.connection.query(sqlStatement.text, sqlStatement.values);

    if (!response || !response.rows.length) {
      throw new HTTP400('Failed to get submission');
    }

    return response.rows[0]?.input_key;
  }

  async getOccurrenceSubmission(occurrenceSubmissionId: number) {
    const sqlStatement = Queries.occurrence.view.getOccurrencesForViewSQL(occurrenceSubmissionId);

    if (!sqlStatement) {
      throw new HTTP400('Failed to build SQL get statement');
    }

    const response = await this.connection.query(sqlStatement.text, sqlStatement.values);

    if (!response || !response.rows.length) {
      throw new HTTP400('Failed to get survey occurrence submission');
    }

    return response.rows[0];
  }

  async scrapeAndUploadOccurrences(occurrenceSubmissionId: number, dwcArchive: DWCArchive) {
    const {
      occurrenceRows,
      occurrenceIdHeader,
      associatedTaxaHeader,
      eventRows,
      lifeStageHeader,
      sexHeader,
      individualCountHeader,
      organismQuantityHeader,
      organismQuantityTypeHeader,
      occurrenceHeaders,
      eventIdHeader,
      eventDateHeader,
      eventVerbatimCoordinatesHeader,
      taxonRows,
      taxonIdHeader,
      vernacularNameHeader
    } = this.getHeadersAndRowsFromFile(dwcArchive);

    const scrapedOccurrences = occurrenceRows?.map((row: any) => {
      const occurrenceId = row[occurrenceIdHeader];
      const associatedTaxa = row[associatedTaxaHeader];
      const lifeStage = row[lifeStageHeader];
      const sex = row[sexHeader];
      const individualCount = row[individualCountHeader];
      const organismQuantity = row[organismQuantityHeader];
      const organismQuantityType = row[organismQuantityTypeHeader];

      const data = { headers: occurrenceHeaders, rows: row };

      let verbatimCoordinates;
      let eventDate;

      eventRows?.forEach((eventRow: any) => {
        if (eventRow[eventIdHeader] === occurrenceId) {
          eventDate = eventRow[eventDateHeader];
          verbatimCoordinates = eventRow[eventVerbatimCoordinatesHeader];
        }
      });

      let vernacularName;

      taxonRows?.forEach((taxonRow: any) => {
        if (taxonRow[taxonIdHeader] === occurrenceId) {
          vernacularName = taxonRow[vernacularNameHeader];
        }
      });

      return new PostOccurrence({
        associatedTaxa: associatedTaxa,
        lifeStage: lifeStage,
        sex: sex,
        individualCount: individualCount,
        vernacularName: vernacularName,
        data,
        verbatimCoordinates: verbatimCoordinates,
        organismQuantity: organismQuantity,
        organismQuantityType: organismQuantityType,
        eventDate: eventDate
      });
    });

    await Promise.all(
      scrapedOccurrences?.map(async (scrapedOccurrence: any) => {
        this.uploadScrapedOccurrence(occurrenceSubmissionId, scrapedOccurrence);
      }) || []
    );
  }

  /**
   * Upload scraped occurrence data.
   *
   * @param {number} occurrenceSubmissionId
   * @param {any} scrapedOccurrence
   * @param {IDBConnection} connection
   * @return {*}
   */
  async uploadScrapedOccurrence(occurrenceSubmissionId: number, scrapedOccurrence: PostOccurrence) {
    const sqlStatement = Queries.occurrence.create.postOccurrenceSQL(occurrenceSubmissionId, scrapedOccurrence);

    if (!sqlStatement) {
      throw new HTTP400('Failed to build SQL post statement');
    }

    const response = await this.connection.query(sqlStatement.text, sqlStatement.values);

    if (!response || !response.rowCount) {
      throw new HTTP400('Failed to insert occurrence data');
    }
  }

  /**
   *
   *
   * @param {DWCArchive} dwcArchive
   * @return {*}
   * @memberof DarwinCoreService
   */
  getHeadersAndRowsFromFile(dwcArchive: DWCArchive) {
    const eventHeaders = dwcArchive.worksheets.event?.getHeaders();
    const eventRows = dwcArchive.worksheets.event?.getRows();

    const eventIdHeader = eventHeaders?.indexOf('id') as number;
    const eventVerbatimCoordinatesHeader = eventHeaders?.indexOf('verbatimCoordinates') as number;
    const eventDateHeader = eventHeaders?.indexOf('eventDate') as number;

    const occurrenceHeaders = dwcArchive.worksheets.occurrence?.getHeaders();
    const occurrenceRows = dwcArchive.worksheets.occurrence?.getRows();

    const occurrenceIdHeader = occurrenceHeaders?.indexOf('id') as number;
    const associatedTaxaHeader = occurrenceHeaders?.indexOf('associatedTaxa') as number;
    const lifeStageHeader = occurrenceHeaders?.indexOf('lifeStage') as number;
    const sexHeader = occurrenceHeaders?.indexOf('sex') as number;
    const individualCountHeader = occurrenceHeaders?.indexOf('individualCount') as number;
    const organismQuantityHeader = occurrenceHeaders?.indexOf('organismQuantity') as number;
    const organismQuantityTypeHeader = occurrenceHeaders?.indexOf('organismQuantityType') as number;

    const taxonHeaders = dwcArchive.worksheets.taxon?.getHeaders();
    const taxonRows = dwcArchive.worksheets.taxon?.getRows();
    const taxonIdHeader = taxonHeaders?.indexOf('id') as number;
    const vernacularNameHeader = taxonHeaders?.indexOf('vernacularName') as number;

    return {
      occurrenceRows,
      occurrenceIdHeader,
      associatedTaxaHeader,
      eventRows,
      lifeStageHeader,
      sexHeader,
      individualCountHeader,
      organismQuantityHeader,
      organismQuantityTypeHeader,
      occurrenceHeaders,
      eventIdHeader,
      eventDateHeader,
      eventVerbatimCoordinatesHeader,
      taxonRows,
      taxonIdHeader,
      vernacularNameHeader
    };
  }
}

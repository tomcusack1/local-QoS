import csv
import datetime
import sys


class QualityScore(object):
    def __init__(self, csv_data_file: str):
        self.csv_data_file = csv_data_file
        self.ip_address = []
        self.timestamp = []
        self.packet_loss = []
        self.min_RTT = []
        self.ave_RTT = []
        self.max_RTT = []
        self.bandwidth = []
        self.pdv = []
        self.raw_quality_score = []
        self.quality_score = tuple()

    def read_data(self):
        """Iterates over daily CSV file reading measurements into memory."""
        with open(self.csv_data_file) as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.ip_address.append(row['IP Address'])
                self.timestamp.append(row['Timestamp'])
                self.packet_loss.append(row['Packet Loss'])
                self.min_RTT.append(row['Min RTT'])
                self.ave_RTT.append(row['Ave RTT'])
                self.max_RTT.append(row['Max RTT'])
                self.bandwidth.append(row['Bandwidth'])
                self.pdv.append(row['Packet Delay Variation'])

    def generate_score(self):

        def get_start_hour(time: list) -> tuple:
            """Returns a list of the ith position where a new block starts, plus the numeric hour"""
            start_positions = []
            pos = []
            for i, hour in enumerate(time):
                if hour[11:13] not in start_positions:
                    start_positions.append(hour[11:13])
                    pos.append(i)
            return pos

        def aggregate_hourly_data(data):
            # Hourly data is here to be aggregated and a quality score produced
            #     Fields are [0] Average RTT; [1] Bandwidth; [2] Packet Loss; [3] Jitter
            #     data[0]: 00:00 --> 00:59.  data[1]: 01:00 --> 01:59
            qs = []
            for hourly_data in data:
                quality_score = (float(hourly_data[0]) / 2) + (float(hourly_data[1]) * 1000) + \
                                (float(hourly_data[2])) + (float(hourly_data[3]) * 100)
                qs.append(quality_score)
            self.raw_quality_score.append(sum(qs) / len(qs))

        def analyse_data(i_data):
            # Gets the ith range between the hourly ranges, and zips the hourly data together
            for i in range(len(i_data) - 1):
                a, b = i_data[i], i_data[i + 1]
                start, stop = (a, b - 1)

                # Store hourly data
                hourly_data = []

                for j in range(start, stop):
                    row = self.ave_RTT[j], self.bandwidth[j], self.packet_loss[j], self.pdv[j]
                    hourly_data.append(row)

                # Got data compressed as a list object in hourly_data[]
                # Time to fire this to our calculate method to get hourly quality aggregated data
                # print("\n\nNEW HOUR BLOCK")
                aggregate_hourly_data(hourly_data)

        def prepare_data():
            hours = ['00:00', '01:00', '02:00', '03:00', '04:00', '05:00', '06:00', '07:00', '08:00', '09:00', '10:00',
                     '11:00', '12:00', '13:00', '14:00', '15:00', '16:00', '17:00', '18:00', '19:00', '20:00', '21:00',
                     '22:00', '23:00']
            date = list()
            for _ in range(25):
                date.append(str(datetime.date.today()))
            self.quality_score = (list(zip(date + hours, self.raw_quality_score)))

        # Start analysis
        analyse_data(get_start_hour(self.timestamp))
        prepare_data()

    def export_data(self):
        with open('quality_data.csv', "a", newline='') as csv_file:
            writer = csv.writer(csv_file, delimiter=',')
            for line in self.quality_score:
                writer.writerow(line)


def main():
    try:
        generate_quality_score = QualityScore(str(datetime.date.today()) + '.csv')
        generate_quality_score.read_data()
        generate_quality_score.generate_score()
        generate_quality_score.export_data()

    except FileNotFoundError as error:
        raise error.with_traceback(sys.exc_info()[2])

if __name__ == '__main__':
    main()

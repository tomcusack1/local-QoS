import csv


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

    def read_data(self):
        """Iterates over daily CSV file reading measurements into memory."""
        with open(self.csv_data_file) as file:
            reader = csv.DictReader(file)
            for row in reader:
                self.ip_address.append(row['P Address'])
                self.timestamp.append(row['Timestamp'])
                self.packet_loss.append(row['Packet Loss'])
                self.min_RTT.append(row['Min RTT'])
                self.ave_RTT.append(row['Ave RTT'])
                self.max_RTT.append(row['Max RTT'])
                self.bandwidth.append(row['Bandwidth'])
                self.pdv.append(row[' Packet Delay Variation'])

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
            for hourly_data in data:
                # print("\nMinute of data.")
                for measurements in hourly_data:
                    # Loop over the measurements.
                    # These are:
                    #   Ave RTT --> Bandwidth --> Packet Loss --> PDV
                    print(measurements)

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
                print("\n\nNEW HOUR BLOCK")
                aggregate_hourly_data(hourly_data)

        # Start analysis
        analyse_data(get_start_hour(self.timestamp))


def main():
    generate_quality_score = QualityScore('2017-01-26.csv')
    generate_quality_score.read_data()
    generate_quality_score.generate_score()

if __name__ == '__main__':
    main()

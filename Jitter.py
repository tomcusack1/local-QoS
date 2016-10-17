class Jitter(object):
    def __init__(self):
        self.jitter = [0, 1, 2, 3, 4, 5, 6, 7]
        self.time_sent = []
        self.time_received = []

    def _calculate_jitter(self):
        difference_relative_transit_times = (self.time_received[0] - self.time_received[1]) \
                                            - (self.time_sent[0] - self.time_sent[1])

        return self.jitter.append(self.jitter[1 - 1] + (abs(difference_relative_transit_times)
                                  - self.jitter[1 - 1]) / float(16))

    def add_time_sent_measurement(self, measurement):
        return self.time_sent.insert(0, measurement)

    def add_time_received_measurement(self, measurement):
        return self.time_received.insert(0, measurement)

    def get_jitter(self):
        return self.jitter

j = Jitter()
j.add_time_sent_measurement(1)
j.add_time_sent_measurement(2)
j.add_time_sent_measurement(3)
j.add_time_sent_measurement(4)
j.add_time_sent_measurement(5)
j.add_time_received_measurement(3)
j.add_time_received_measurement(4)
j.add_time_received_measurement(5)
j.add_time_received_measurement(6)
j.add_time_received_measurement(7)
j._calculate_jitter()
print j.get_jitter()
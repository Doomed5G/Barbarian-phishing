"""Image forensics analysis tool for detecting manipulated or suspicious images."""

from pathlib import Path
from datetime import datetime
from typing import Dict, List

try:
    from PIL import Image
    from PIL.ExifTags import TAGS
    HAS_PIL = True
except ImportError:
    HAS_PIL = False

try:
    import numpy as np
    HAS_NUMPY = True
except ImportError:
    HAS_NUMPY = False

import io


class ImageForensicsAnalyzer:
    """Performs forensic analysis on image files to detect manipulation,
    metadata inconsistencies, steganography indicators, and other anomalies."""

    def analyze(self, filepath: Path) -> Dict:
        """Run all forensic checks on an image and return merged findings.

        Args:
            filepath: Path to the image file to analyze.

        Returns:
            Dict with tool_name, timestamp, findings list, and tools_used list.
        """
        filepath = Path(filepath)
        result = {
            'tool_name': 'Image Forensics',
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'tools_used': []
        }

        if not HAS_PIL:
            result['findings'].append({
                'severity': 'ERROR',
                'category': 'Dependency Missing',
                'message': 'Pillow (PIL) is not installed',
                'details': 'Install with: pip install Pillow'
            })
            return result

        if not HAS_NUMPY:
            result['findings'].append({
                'severity': 'ERROR',
                'category': 'Dependency Missing',
                'message': 'NumPy is not installed',
                'details': 'Install with: pip install numpy'
            })
            return result

        checks = [
            ('Error Level Analysis', self._error_level_analysis),
            ('Metadata Consistency', self._metadata_consistency),
            ('Thumbnail Comparison', self._thumbnail_comparison),
            ('EXIF Stripping Detection', self._exif_stripping_detection),
            ('LSB Statistical Analysis', self._lsb_statistical_analysis),
        ]

        for check_name, check_fn in checks:
            try:
                check_result = check_fn(filepath)
                result['findings'].extend(check_result.get('findings', []))
                result['tools_used'].append({
                    'name': check_name,
                    'status': 'success',
                    'type': 'forensic',
                    'timestamp': datetime.now().isoformat()
                })
            except Exception as e:
                result['findings'].append({
                    'severity': 'ERROR',
                    'category': check_name,
                    'message': f'{check_name} failed: {str(e)}',
                    'details': f'Exception during {check_name}'
                })
                result['tools_used'].append({
                    'name': check_name,
                    'status': 'error',
                    'type': 'forensic',
                    'timestamp': datetime.now().isoformat()
                })

        return result

    def _error_level_analysis(self, filepath: Path) -> Dict:
        """Perform Error Level Analysis (ELA) on JPEG images.

        Re-saves the image at quality=95 and compares pixel arrays to detect
        regions that were edited or re-compressed at different quality levels.

        Args:
            filepath: Path to the image file.

        Returns:
            Dict with findings list.
        """
        findings = []

        try:
            img = Image.open(filepath)

            # ELA only applies to JPEG images
            if img.format not in ('JPEG', 'JPG', 'MPO'):
                findings.append({
                    'severity': 'INFO',
                    'category': 'Error Level Analysis',
                    'message': f'ELA skipped: image format is {img.format}, not JPEG',
                    'details': 'Error Level Analysis is only meaningful for JPEG images'
                })
                return {'findings': findings}

            # Re-save at quality 95
            buffer = io.BytesIO()
            img.save(buffer, format='JPEG', quality=95)
            buffer.seek(0)
            resaved = Image.open(buffer)

            # Convert both to numpy arrays for comparison
            original_arr = np.array(img.convert('RGB'), dtype=np.float64)
            resaved_arr = np.array(resaved.convert('RGB'), dtype=np.float64)

            # Compute the absolute difference
            diff = np.abs(original_arr - resaved_arr)
            std_diff = np.std(diff)
            mean_diff = np.mean(diff)

            # Overall ELA check: high standard deviation suggests editing
            if std_diff > 15:
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'Error Level Analysis',
                    'message': 'Elevated error levels detected across image',
                    'details': (f'Standard deviation of ELA difference: {std_diff:.2f} '
                                f'(threshold: 15), mean difference: {mean_diff:.2f}')
                })

            # Block-wise analysis for localized editing detection
            block_size = 64
            height, width = diff.shape[:2]
            overall_mean = np.mean(diff)

            max_block_mean = 0.0
            max_block_pos = (0, 0)

            for y in range(0, height - block_size + 1, block_size):
                for x in range(0, width - block_size + 1, block_size):
                    block = diff[y:y + block_size, x:x + block_size]
                    block_mean = np.mean(block)
                    if block_mean > max_block_mean:
                        max_block_mean = block_mean
                        max_block_pos = (x, y)

            if max_block_mean > 3 * overall_mean and max_block_mean > 20:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Error Level Analysis',
                    'message': 'Localized editing detected in image region',
                    'details': (f'Block at ({max_block_pos[0]}, {max_block_pos[1]}) has '
                                f'mean ELA value {max_block_mean:.2f}, which is '
                                f'{max_block_mean / overall_mean:.1f}x the overall mean '
                                f'({overall_mean:.2f}). This suggests localized manipulation.')
                })

            if not findings:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Error Level Analysis',
                    'message': 'No significant error level anomalies detected',
                    'details': (f'ELA std deviation: {std_diff:.2f}, '
                                f'overall mean: {mean_diff:.2f}')
                })

        except Exception as e:
            findings.append({
                'severity': 'ERROR',
                'category': 'Error Level Analysis',
                'message': f'ELA failed: {str(e)}',
                'details': str(e)
            })

        return {'findings': findings}

    def _metadata_consistency(self, filepath: Path) -> Dict:
        """Check EXIF metadata for inconsistencies and indicators of editing.

        Looks for editing software tags, GPS data, and date inconsistencies
        between DateTimeOriginal, DateTimeDigitized, and DateTime fields.

        Args:
            filepath: Path to the image file.

        Returns:
            Dict with findings list.
        """
        findings = []

        try:
            img = Image.open(filepath)

            # Try to get EXIF data
            exif_raw = img._getexif() if hasattr(img, '_getexif') else None

            if exif_raw is None:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Metadata Consistency',
                    'message': 'No EXIF metadata found in image',
                    'details': 'Image contains no EXIF data to analyze'
                })
                return {'findings': findings}

            # Decode EXIF tags
            exif_data = {}
            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                exif_data[tag_name] = value

            # Check for editing software
            software = exif_data.get('Software', '')
            if software:
                software_lower = str(software).lower()
                editing_tools = ['photoshop', 'gimp', 'paint']
                for tool in editing_tools:
                    if tool in software_lower:
                        findings.append({
                            'severity': 'MEDIUM',
                            'category': 'Metadata Consistency',
                            'message': f'Image editing software detected: {software}',
                            'details': (f'The Software EXIF tag contains "{software}", '
                                        f'indicating the image was processed with editing software')
                        })
                        break

            # Check for GPS data
            gps_tags = ['GPSInfo', 'GPSLatitude', 'GPSLongitude']
            gps_present = any(tag in exif_data for tag in gps_tags)
            if gps_present:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Metadata Consistency',
                    'message': 'GPS location data present in image',
                    'details': 'Image contains GPS coordinates in EXIF metadata'
                })

            # Check date consistency
            date_fields = {
                'DateTimeOriginal': exif_data.get('DateTimeOriginal'),
                'DateTimeDigitized': exif_data.get('DateTimeDigitized'),
                'DateTime': exif_data.get('DateTime'),
            }

            present_dates = {k: str(v) for k, v in date_fields.items() if v is not None}

            if len(present_dates) >= 2:
                unique_dates = set(present_dates.values())
                if len(unique_dates) > 1:
                    date_details = ', '.join(
                        f'{k}={v}' for k, v in present_dates.items()
                    )
                    findings.append({
                        'severity': 'MEDIUM',
                        'category': 'Metadata Consistency',
                        'message': 'Date inconsistency detected in EXIF metadata',
                        'details': (f'Multiple date fields contain different values: '
                                    f'{date_details}. This may indicate metadata tampering.')
                    })

            if not findings:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Metadata Consistency',
                    'message': 'EXIF metadata appears consistent',
                    'details': f'Checked {len(exif_data)} EXIF tags, no inconsistencies found'
                })

        except Exception as e:
            findings.append({
                'severity': 'ERROR',
                'category': 'Metadata Consistency',
                'message': f'Metadata analysis failed: {str(e)}',
                'details': str(e)
            })

        return {'findings': findings}

    def _thumbnail_comparison(self, filepath: Path) -> Dict:
        """Compare embedded JPEG thumbnail with the main image.

        If the thumbnail does not match the main image (mean pixel difference > 30),
        it may indicate the image was modified after the thumbnail was generated.

        Args:
            filepath: Path to the image file.

        Returns:
            Dict with findings list.
        """
        findings = []

        try:
            img = Image.open(filepath)

            exif_raw = img._getexif() if hasattr(img, '_getexif') else None
            if exif_raw is None:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Thumbnail Comparison',
                    'message': 'No EXIF data available for thumbnail comparison',
                    'details': 'Cannot extract embedded thumbnail without EXIF data'
                })
                return {'findings': findings}

            # Tags 0x0201 (JpegIFOffset) and 0x0202 (JpegIFByteCount)
            thumb_offset = exif_raw.get(0x0201)
            thumb_length = exif_raw.get(0x0202)

            if thumb_offset is None or thumb_length is None:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Thumbnail Comparison',
                    'message': 'No embedded thumbnail found in image',
                    'details': 'EXIF tags 0x0201/0x0202 (thumbnail offset/length) not present'
                })
                return {'findings': findings}

            # Read the raw file to extract the thumbnail bytes
            with open(filepath, 'rb') as f:
                raw_data = f.read()

            # Extract thumbnail data
            thumb_data = raw_data[thumb_offset:thumb_offset + thumb_length]

            if len(thumb_data) == 0:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Thumbnail Comparison',
                    'message': 'Embedded thumbnail is empty',
                    'details': 'Thumbnail data has zero length'
                })
                return {'findings': findings}

            # Open the thumbnail
            thumb_img = Image.open(io.BytesIO(thumb_data)).convert('RGB')
            thumb_size = thumb_img.size

            # Resize main image to thumbnail size for comparison
            main_resized = img.convert('RGB').resize(thumb_size, Image.LANCZOS)

            # Compare pixel arrays
            thumb_arr = np.array(thumb_img, dtype=np.float64)
            main_arr = np.array(main_resized, dtype=np.float64)

            diff_mean = np.mean(np.abs(thumb_arr - main_arr))

            if diff_mean > 30:
                findings.append({
                    'severity': 'HIGH',
                    'category': 'Thumbnail Comparison',
                    'message': 'Thumbnail does not match main image',
                    'details': (f'Mean pixel difference between embedded thumbnail and '
                                f'resized main image: {diff_mean:.2f} (threshold: 30). '
                                f'This strongly suggests the image was modified after the '
                                f'thumbnail was generated.')
                })
            else:
                findings.append({
                    'severity': 'INFO',
                    'category': 'Thumbnail Comparison',
                    'message': 'Thumbnail matches main image',
                    'details': f'Mean pixel difference: {diff_mean:.2f} (threshold: 30)'
                })

        except Exception as e:
            findings.append({
                'severity': 'ERROR',
                'category': 'Thumbnail Comparison',
                'message': f'Thumbnail comparison failed: {str(e)}',
                'details': str(e)
            })

        return {'findings': findings}

    def _exif_stripping_detection(self, filepath: Path) -> Dict:
        """Detect if EXIF data has been intentionally stripped from a JPEG.

        A JPEG with no EXIF at all is mildly suspicious (LOW). A file with
        camera information but missing date fields suggests selective stripping (MEDIUM).

        Args:
            filepath: Path to the image file.

        Returns:
            Dict with findings list.
        """
        findings = []

        try:
            img = Image.open(filepath)

            # Only meaningful for JPEGs
            is_jpeg = img.format in ('JPEG', 'JPG', 'MPO')

            exif_raw = img._getexif() if hasattr(img, '_getexif') else None

            if is_jpeg and exif_raw is None:
                findings.append({
                    'severity': 'LOW',
                    'category': 'EXIF Stripping Detection',
                    'message': 'JPEG image contains no EXIF metadata',
                    'details': ('JPEG files from cameras typically contain EXIF data. '
                                'Its absence may indicate intentional stripping.')
                })
                return {'findings': findings}

            if exif_raw is None:
                findings.append({
                    'severity': 'INFO',
                    'category': 'EXIF Stripping Detection',
                    'message': f'No EXIF data found (format: {img.format})',
                    'details': 'Non-JPEG formats may not include EXIF data by default'
                })
                return {'findings': findings}

            # Decode tags
            exif_data = {}
            for tag_id, value in exif_raw.items():
                tag_name = TAGS.get(tag_id, str(tag_id))
                exif_data[tag_name] = value

            # Check if camera info is present
            camera_tags = ['Make', 'Model', 'LensModel', 'LensMake']
            has_camera_info = any(tag in exif_data for tag in camera_tags)

            # Check if date fields are present
            date_tags = ['DateTimeOriginal', 'DateTimeDigitized', 'DateTime']
            has_dates = any(tag in exif_data for tag in date_tags)

            if has_camera_info and not has_dates:
                camera_info = ', '.join(
                    f'{tag}={exif_data[tag]}' for tag in camera_tags
                    if tag in exif_data
                )
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'EXIF Stripping Detection',
                    'message': 'Camera info present but date fields removed',
                    'details': (f'Camera metadata found ({camera_info}) but all date '
                                f'fields (DateTimeOriginal, DateTimeDigitized, DateTime) '
                                f'are missing. This suggests selective EXIF stripping.')
                })

            if not findings:
                findings.append({
                    'severity': 'INFO',
                    'category': 'EXIF Stripping Detection',
                    'message': 'EXIF data appears complete',
                    'details': (f'Camera info present: {has_camera_info}, '
                                f'Date fields present: {has_dates}')
                })

        except Exception as e:
            findings.append({
                'severity': 'ERROR',
                'category': 'EXIF Stripping Detection',
                'message': f'EXIF stripping detection failed: {str(e)}',
                'details': str(e)
            })

        return {'findings': findings}

    def _lsb_statistical_analysis(self, filepath: Path) -> Dict:
        """Perform Least Significant Bit (LSB) statistical analysis.

        Checks each RGB channel's LSB distribution and transition patterns
        for indicators of steganographic data embedding.

        For each channel:
        - Extract LSBs and check if the ratio of 1s is near 0.49-0.51
        - Count bit transitions and compare to expected (length/2)
        - A transition deviation < 0.01 combined with balanced ratio
          indicates potential steganography (MEDIUM).

        Args:
            filepath: Path to the image file.

        Returns:
            Dict with findings list.
        """
        findings = []

        try:
            img = Image.open(filepath).convert('RGB')
            img_arr = np.array(img, dtype=np.uint8)

            channel_names = ['Red', 'Green', 'Blue']
            stego_indicators = []

            for ch_idx, ch_name in enumerate(channel_names):
                channel = img_arr[:, :, ch_idx].flatten()

                # Extract LSBs
                lsbs = channel & 1

                total_pixels = len(lsbs)
                ones_count = np.sum(lsbs)
                ratio = ones_count / total_pixels

                # Check if ratio is suspiciously balanced (near 0.49-0.51)
                ratio_suspicious = 0.49 <= ratio <= 0.51

                # Transition test: count bit transitions in LSB stream
                transitions = np.sum(np.abs(np.diff(lsbs.astype(np.int8))))
                expected_transitions = total_pixels / 2
                transition_deviation = abs(transitions - expected_transitions) / expected_transitions

                # Low deviation from expected transitions suggests embedded data
                transition_suspicious = transition_deviation < 0.01

                if ratio_suspicious and transition_suspicious:
                    stego_indicators.append({
                        'channel': ch_name,
                        'ratio': ratio,
                        'transition_deviation': transition_deviation
                    })

            if stego_indicators:
                channel_details = '; '.join(
                    f'{ind["channel"]}: ratio={ind["ratio"]:.4f}, '
                    f'transition_dev={ind["transition_deviation"]:.4f}'
                    for ind in stego_indicators
                )
                affected_channels = ', '.join(
                    ind['channel'] for ind in stego_indicators
                )
                findings.append({
                    'severity': 'MEDIUM',
                    'category': 'LSB Statistical Analysis',
                    'message': (f'Steganography indicators detected in '
                                f'{affected_channels} channel(s)'),
                    'details': (f'LSB distribution and transition patterns suggest '
                                f'possible hidden data. {channel_details}')
                })

            if not findings:
                findings.append({
                    'severity': 'INFO',
                    'category': 'LSB Statistical Analysis',
                    'message': 'No steganography indicators detected',
                    'details': 'LSB distribution and transition analysis within normal ranges'
                })

        except Exception as e:
            findings.append({
                'severity': 'ERROR',
                'category': 'LSB Statistical Analysis',
                'message': f'LSB analysis failed: {str(e)}',
                'details': str(e)
            })

        return {'findings': findings}
